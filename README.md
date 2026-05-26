# agdb

A unified, zero-dependency persistent database written entirely in Zig.
It combines a persistent memory-mapped heap, write-ahead logging, an
append-only key-value store with crash recovery, a BM25 full-text search
index, a dense-vector index with cosine/euclidean/inner-product/manhattan
distance metrics, structured records, a JSON encoder/decoder, a REST HTTP
server, and a feature-complete command-line interface.

## Requirements

- Zig 0.14.0

## Build

```bash
zig build
```

Produces the following artifacts under `zig-out/`:

- `zig-out/bin/agdb` — command-line interface and HTTP server
- `zig-out/bin/agdb-runtime` — runtime/snapshot executable
- `zig-out/lib/libagdb.a` — static library

## Test

```bash
zig build test
```

Runs unit tests for every module plus end-to-end integration tests.

## CLI

```bash
agdb <command> [options]
```

Global options:

- `--data,-d <dir>` directory for storage and indexes (default `./agdb-data`)
- `--dim <N>` embedding dimension (default `256`)
- `--bind <addr>` server bind address (default `127.0.0.1`)
- `--port <port>` server port (default `7878`)

Commands:

- `init` create or open the database
- `put <body> [--tag t] [--kind k] [--id N]` store a record
- `put-file <path> [--tag t] [--kind k]` ingest a file
- `put-json [--file path]` ingest JSON from stdin or file
- `get <id>` retrieve a record as JSON
- `del <id>` delete a record
- `search <query> [--k N] [--mode text|hybrid] [--alpha 0.5]` text or hybrid search
- `vector-search "f1,f2,..." [--k N]` vector search
- `list` list all record ids
- `stats` show storage statistics
- `compact` reclaim dead space
- `flush` persist indexes
- `snapshot [path]` copy storage to a snapshot file
- `serve` start the HTTP server

Example session:

```bash
agdb --data ./mydb init
agdb --data ./mydb put "vector embeddings live near records" --tag db
agdb --data ./mydb put "bm25 ranks documents using idf and tf"   --tag fts
agdb --data ./mydb search "bm25 ranking" --k 3
agdb --data ./mydb stats
```

## HTTP Server

```bash
agdb --data ./mydb --bind 0.0.0.0 --port 7878 serve
```

Endpoints:

- `GET  /health`
- `GET  /version`
- `GET  /stats`
- `POST /records`           JSON body: `{ "kind": "document", "body": "...", "tags": ["a","b"] }`
- `POST /search`            JSON body: `{ "query": "text", "k": 5, "mode": "hybrid", "alpha": 0.5 }`
- `POST /compact`
- `POST /flush`
- `GET  /records/<id>`
- `DELETE /records/<id>`

Bearer-token auth is supported via the `api_token` configuration field.

## Library Use

```zig
const agdb = @import("agdb");

var db = try agdb.Database.open(allocator, .{ .data_dir = "./mydb" });
defer db.close();

const empty: [0][]const u8 = .{};
const id = try db.putBytes(.document, 0, "hello world", &empty);

var results = try db.searchText("hello", 5);
defer results.deinit();
```

## Architecture

- `pheap.zig` persistent memory-mapped heap with checksumming
- `wal.zig` write-ahead log with crash-safe transactions
- `allocator.zig` persistent allocator with size classes and MPSC-deferred free
- `transaction.zig` transaction manager with conflict detection
- `gc.zig` reference-count garbage collector with mark/sweep fallback
- `snapshot.zig` page-granular snapshots with merkle verification
- `security.zig` AES-GCM and ChaCha20-Poly1305 envelope encryption
- `recovery.zig` heap repair and journal replay
- `schema.zig` typed schema registry with migration
- `kv.zig` append-only key-value store with crash-safe records
- `bm25.zig` BM25 inverted index (k1=1.5, b=0.75)
- `vector.zig` dense vector index with multiple distance metrics
- `tokenizer.zig` UTF-8 tokenizer with stopword handling and n-grams
- `record.zig` structured record encoder/decoder
- `json.zig` JSON parser and serializer
- `database.zig` unified database that wires the above together
- `server.zig` REST HTTP server on top of `std.http`
- `cli.zig` command-line dispatcher
