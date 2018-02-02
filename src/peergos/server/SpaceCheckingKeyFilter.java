package peergos.server;

import peergos.server.corenode.*;
import peergos.server.mutable.*;
import peergos.shared.cbor.*;
import peergos.shared.corenode.*;
import peergos.shared.crypto.hash.*;
import peergos.shared.io.ipfs.api.JSONParser;
import peergos.shared.merklebtree.*;
import peergos.shared.mutable.*;
import peergos.shared.storage.*;
import peergos.shared.user.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import java.util.stream.Collectors;

/** This class checks whether a given user is using more storage space than their quota
 *
 */
public class SpaceCheckingKeyFilter  {
    private static final long DEFAULT_STORE_PERIOD = 60*1000*10; //10M
    private final CoreNode core;
    private final MutablePointers mutable;
    private final ContentAddressedStorage dht;
    private Function<String, Long> quotaSupplier;
    private final Path statePath;
    private final State state;
    private final Map<PublicKeyHash, Stat> currentView;
    private final Map<String, Usage> usage;

    public static class State implements Cborable {
        final Map<PublicKeyHash, Stat> currentView;
        final Map<String, Usage> usage;

        public State(Map<PublicKeyHash, Stat> currentView, Map<String, Usage> usage) {
            this.currentView = currentView;
            this.usage = usage;
        }

        @Override
        public CborObject toCbor() {
            TreeMap<CborObject, ? extends Cborable> viewsMap = currentView.entrySet()
                .stream()
                .collect(Collectors.toMap(
                    e -> e.getKey().toCbor(),
                    e -> (Cborable) (e.getValue()),
                    (a,b) -> a,
                    () -> new TreeMap<>()
                ));

            CborObject.CborMap views = new CborObject.CborMap(viewsMap);
            CborObject.CborMap usages = CborObject.CborMap.build(usage);
            Map<String, Cborable> map = new HashMap<>();
            map.put("views", views);
            map.put("usages", usages);
            return CborObject.CborMap.build(map);
        }

        public Map<String, Usage> getUsage() {
            return new ConcurrentHashMap<>(usage);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            State state = (State) o;

            if (currentView != null ? !currentView.equals(state.currentView) : state.currentView != null) return false;
            return usage != null ? usage.equals(state.usage) : state.usage == null;
        }

        @Override
        public int hashCode() {
            int result = currentView != null ? currentView.hashCode() : 0;
            result = 31 * result + (usage != null ? usage.hashCode() : 0);
            return result;
        }
    }

    public static State fromCbor(CborObject cbor) {
        CborObject.CborMap map = (CborObject.CborMap) cbor;
        CborObject.CborMap viewsMap = (CborObject.CborMap) map.get("views");
        CborObject.CborMap usagesMap = (CborObject.CborMap) map.get("usages");

        return new State(
            viewsMap.getMap(PublicKeyHash::fromCbor, Stat::fromCbor),
            usagesMap.getMap(
                e -> ((CborObject.CborString) e).value,
                Usage::fromCbor));
    }

    public static class Stat implements Cborable {
        public final String owner;
        private MaybeMultihash target;
        private long directRetainedStorage;
        private Set<PublicKeyHash> ownedKeys;

        public Stat(String owner, MaybeMultihash target, long directRetainedStorage, Set<PublicKeyHash> ownedKeys) {
            this.owner = owner;
            this.target = target;
            this.directRetainedStorage = directRetainedStorage;
            this.ownedKeys = ownedKeys;
        }

        public synchronized void update(MaybeMultihash target, Set<PublicKeyHash> ownedKeys, long retainedStorage) {
            this.target = target;
            this.ownedKeys = Collections.unmodifiableSet(ownedKeys);
            this.directRetainedStorage = retainedStorage;
        }

        public synchronized long getDirectRetainedStorage() {
            return directRetainedStorage;
        }

        public synchronized MaybeMultihash getRoot() {
            return target;
        }

        public synchronized Set<PublicKeyHash> getOwnedKeys() {
            return Collections.unmodifiableSet(ownedKeys);
        }

        @Override
        public CborObject toCbor() {
            Map<String, Cborable> map = new HashMap<>();
            map.put("owner", new CborObject.CborString(owner));
            map.put("target", target);
            map.put("storage", new CborObject.CborLong(directRetainedStorage));
            map.put("ownedKey", new CborObject.CborList(ownedKeys.stream().collect(Collectors.toList())));
            return CborObject.CborMap.build(map);
        }

        public static Stat fromCbor(Cborable cbor) {
            CborObject.CborMap map = (CborObject.CborMap) cbor;
            String owner = map.getString("owner");
            MaybeMultihash target = map.get("target", MaybeMultihash::fromCbor);
            long storage  = map.getLong("storage");
            List<PublicKeyHash> ownedKeys = map.getList("ownedKey").map(PublicKeyHash::fromCbor);
            return new Stat(owner, target, storage, new HashSet<>(ownedKeys));
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Stat stat = (Stat) o;

            if (directRetainedStorage != stat.directRetainedStorage) return false;
            if (owner != null ? !owner.equals(stat.owner) : stat.owner != null) return false;
            if (target != null ? !target.equals(stat.target) : stat.target != null) return false;
            return ownedKeys != null ? ownedKeys.equals(stat.ownedKeys) : stat.ownedKeys == null;
        }

        @Override
        public int hashCode() {
            int result = owner != null ? owner.hashCode() : 0;
            result = 31 * result + (target != null ? target.hashCode() : 0);
            result = 31 * result + (int) (directRetainedStorage ^ (directRetainedStorage >>> 32));
            result = 31 * result + (ownedKeys != null ? ownedKeys.hashCode() : 0);
            return result;
        }
    }

    public static class Usage implements Cborable {
        private long usage;
        private Map<PublicKeyHash, Long> pending = new HashMap<>();

        public Usage(long usage) {
            this.usage = usage;
        }

        protected synchronized void confirmUsage(PublicKeyHash writer, long usageDelta) {
            pending.remove(writer);
            usage += usageDelta;
        }

        protected synchronized void addPending(PublicKeyHash writer, long usageDelta) {
            pending.put(writer, pending.getOrDefault(writer, 0L) + usageDelta);
        }

        protected synchronized void clearPending(PublicKeyHash writer) {
            pending.remove(writer);
        }

        protected synchronized long getPending(PublicKeyHash writer) {
            return pending.getOrDefault(writer, 0L);
        }

        protected synchronized long usage() {
            return usage + pending.values().stream().mapToLong(x -> x).sum();
        }

        @Override
        public CborObject toCbor() {
            return new CborObject.CborLong(usage);
        }

        public static Usage fromCbor(Cborable cborable) {
            long usage = ((CborObject.CborLong) cborable).value;
            return new Usage(usage);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Usage usage1 = (Usage) o;

            if (usage != usage1.usage) return false;
            return pending != null ? pending.equals(usage1.pending) : usage1.pending == null;
        }

        @Override
        public int hashCode() {
            int result = (int) (usage ^ (usage >>> 32));
            result = 31 * result + (pending != null ? pending.hashCode() : 0);
            return result;
        }
    }

    /**
     *
     * @param core
     * @param mutable
     * @param dht
     * @param quotaSupplier The quota supplier
     * @param statePath path to local file with user usages
     */
    public SpaceCheckingKeyFilter(CoreNode core,
                                  MutablePointers mutable,
                                  ContentAddressedStorage dht,
                                  Function<String, Long> quotaSupplier,
                                  Path statePath) throws IOException{
        this.core = core;
        this.mutable = mutable;
        this.dht = dht;
        this.quotaSupplier = quotaSupplier;
        this.statePath = statePath;
        this.state = initState();
        this.currentView  = state.currentView;
        this.usage = state.usage;
    }

    /**
     *
     */
    private State initState() throws IOException {
        State state = null;
        try {
            // Read stored usages and udate current view.
            state = load();
            System.out.println("Successfully loaded usage-state from "+ this.statePath);
        } catch (IOException ioe) {
            System.out.println("Could not read usage-state from "+ this.statePath);
            // calculate usage from scratch
            state = new State(
                new ConcurrentHashMap<>(),
                new ConcurrentHashMap<>());
        }
        try {
            for (Map.Entry<PublicKeyHash, Stat> entry : state.currentView.entrySet()) {
                PublicKeyHash writerKey = entry.getKey();
                Stat stat = entry.getValue();
                MaybeMultihash rootHash = mutable.getPointerTarget(writerKey, dht).get();
                boolean isChanged = stat.target.equals(rootHash);
                if (isChanged) {
                    long updatedSize = dht.getRecursiveBlockSize(rootHash.get()).get();
                    long deltaUsage = updatedSize - stat.directRetainedStorage;
                    state.usage.get(stat.owner).confirmUsage(writerKey, deltaUsage); //NB: writerKey is a dummy value
                    Set<PublicKeyHash> directOwnedKeys = WriterData.getDirectOwnedKeys(writerKey, mutable, dht);
                    List<PublicKeyHash> newOwnedKeys = directOwnedKeys.stream()
                        .filter(key -> !stat.ownedKeys.contains(key))
                        .collect(Collectors.toList());
                    for (PublicKeyHash newOwnedKey : newOwnedKeys) {
                        currentView.putIfAbsent(newOwnedKey, new Stat(stat.owner, MaybeMultihash.empty(), 0, Collections.emptySet()));
                        processMutablePointerEvent(newOwnedKey, MaybeMultihash.empty(), mutable.getPointerTarget(newOwnedKey, dht).get());
                    }
                    stat.update(rootHash, directOwnedKeys, updatedSize);
                }
            }
        } catch (InterruptedException | ExecutionException ex) {
                throw new IOException(ex);
        }
        calculateUsage();
        //add shutdown-hook to call close
        Runtime.getRuntime().addShutdownHook(new Thread(this::close));
        //remove state-path
        Files.deleteIfExists(statePath);
        return state;
    }

    /**
     * Write current view of usages to this.statePath, completing any pending operations
     */
    private void close() {
        try {
            store();
            System.out.println("Successfully stored usage-state to " + this.statePath);
        } catch (Throwable t) {
            System.out.println("Failed to  store "+ this);
            t.printStackTrace();
        }
    }
    /**
     * Read local file with cached user usages.
     * @return previous usages
     * @throws IOException
     */
    private State load() throws IOException {
        System.out.println("Reading state from "+ statePath +" which exists ? "+ Files.exists(statePath) +" from cwd "+ System.getProperty("cwd"));
        byte[] data = Files.readAllBytes(statePath);
        CborObject object = CborObject.deserialize(new CborDecoder(new ByteArrayInputStream(data)), 1000);
        return fromCbor(object);
    }

    /**
     * Store usages
     * @throws IOException
     */
    private void store() throws IOException {
        byte[] serialized = state.toCbor().serialize();
        System.out.println("Writing "+ serialized.length +" bytes to "+ statePath);
        Files.write(
            statePath,
            serialized,
            StandardOpenOption.CREATE);
    }

    /**
     * Walk the virtual file-system to calculate space used by each owner.
     */
    private void calculateUsage() {
        try {
            List<String> usernames = core.getUsernames("").get()
                .stream()
                .filter(usage::containsKey)
                .collect(Collectors.toList());

            for (String username : usernames) {
                Optional<PublicKeyHash> publicKeyHash = core.getPublicKeyHash(username).get();
                publicKeyHash.ifPresent(keyHash -> processCorenodeEvent(username, keyHash));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void accept(CorenodeEvent event) {
        currentView.computeIfAbsent(event.keyHash, k -> new Stat(event.username, MaybeMultihash.empty(), 0, Collections.emptySet()));
        usage.putIfAbsent(event.username, new Usage(0));
        ForkJoinPool.commonPool().submit(() -> processCorenodeEvent(event.username, event.keyHash));
    }

    /** Update our view of the world because a user has changed their public key (or registered)
     *
     * @param username
     * @param ownedKeyHash
     */
    public void processCorenodeEvent(String username, PublicKeyHash ownedKeyHash) {
        try {
            usage.putIfAbsent(username, new Usage(0));
            Set<PublicKeyHash> childrenKeys = WriterData.getDirectOwnedKeys(ownedKeyHash, mutable, dht);
            currentView.computeIfAbsent(ownedKeyHash, k -> new Stat(username, MaybeMultihash.empty(), 0, childrenKeys));
            Stat current = currentView.get(ownedKeyHash);
            MaybeMultihash updatedRoot = mutable.getPointerTarget(ownedKeyHash, dht).get();
            processMutablePointerEvent(ownedKeyHash, current.target, updatedRoot);
            for (PublicKeyHash childKey : childrenKeys) {
                processCorenodeEvent(username, childKey);
            }
        } catch (Throwable e) {
            System.err.println("Error loading storage for user: " + username);
            e.printStackTrace();
        }
    }

    public void accept(MutableEvent event) {
        try {
            HashCasPair hashCasPair = dht.getSigningKey(event.writer)
                    .thenApply(signer -> HashCasPair.fromCbor(CborObject.fromByteArray(signer.get()
                            .unsignMessage(event.writerSignedBtreeRootHash)))).get();
            processMutablePointerEvent(event.writer, hashCasPair.original, hashCasPair.updated);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void processMutablePointerEvent(PublicKeyHash writer, MaybeMultihash existingRoot, MaybeMultihash newRoot) {
        if (existingRoot.equals(newRoot))
            return;
        Stat current = currentView.get(writer);
        if (current == null)
            throw new IllegalStateException("Unknown writer key hash: " + writer);
        if (! newRoot.isPresent()) {
            current.update(MaybeMultihash.empty(), Collections.emptySet(), 0);
            if (existingRoot.isPresent()) {
                try {
                    // subtract data size from orphaned child keys (this assumes the keys form a tree without dups)
                    Set<PublicKeyHash> updatedOwned = WriterData.getWriterData(writer, newRoot, dht).get().props.ownedKeys;
                    processRemovedOwnedKeys(updatedOwned);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            return;
        }

        try {
            synchronized (current) {
                long changeInStorage = dht.getChangeInContainedSize(current.target, newRoot.get()).get();
                Set<PublicKeyHash> updatedOwned = WriterData.getWriterData(writer, newRoot, dht).get().props.ownedKeys;
                for (PublicKeyHash owned : updatedOwned) {
                    currentView.computeIfAbsent(owned, k -> new Stat(current.owner, MaybeMultihash.empty(), 0, Collections.emptySet()));
                }
                Usage currentUsage = usage.get(current.owner);
                currentUsage.confirmUsage(writer, changeInStorage);

                HashSet<PublicKeyHash> removedChildren = new HashSet<>(current.getOwnedKeys());
                removedChildren.removeAll(updatedOwned);
                processRemovedOwnedKeys(removedChildren);
                current.update(newRoot, updatedOwned, current.directRetainedStorage + changeInStorage);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void processRemovedOwnedKeys(Set<PublicKeyHash> removed) {
        for (PublicKeyHash ownedKey : removed) {
            try {
                MaybeMultihash currentTarget = mutable.getPointerTarget(ownedKey, dht).get();
                processMutablePointerEvent(ownedKey, currentTarget, MaybeMultihash.empty());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public boolean allowWrite(PublicKeyHash writer, int size) {
        Stat state = currentView.get(writer);
        if (state == null)
            throw new IllegalStateException("Unknown writing key hash: " + writer);

        Usage usage = this.usage.get(state.owner);
        long spaceUsed = usage.usage();
        long quota = quotaSupplier.apply(state.owner);
        if (spaceUsed > quota || quota - spaceUsed - size <= 0) {
            long pending = usage.getPending(writer);
            usage.clearPending(writer);
            throw new IllegalStateException("Storage quota reached! Used "
                    + usage.usage + " out of " + quota + " bytes. Rejecting write of size " + (size + pending) + ". Please delete some files.");
        }
        usage.addPending(writer, size);
        return true;
    }
}
