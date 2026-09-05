#!/usr/bin/env bash
#
# demo.sh - Node- and relationship-level access control for SQL/PGQ
#           (GRAPH_TABLE) using PostgreSQL row-level security (RLS).
#
# The demo builds a small "social" property graph whose vertex and edge
# tables each carry two access-control properties:
#
#     clevel        integer   - classification level of the element
#     compartments  text[]    - compartments a reader must hold
#
# A single RLS policy per element table decides, for the *current user*,
# whether a row (i.e. a node or an edge) is visible.  Because GRAPH_TABLE is
# rewritten into an ordinary query over the element tables, every MATCH
# pattern is automatically filtered by those policies: hidden nodes cannot be
# returned, hidden edges cannot be traversed, and a path cannot be "queried
# through" a hidden intermediate node or edge.
#
# Requirements
#   * PostgreSQL 19 (or a development build with SQL/PGQ support).
#   * psql on PATH (or PSQL=/path/to/psql).
#   * A connection as a SUPERUSER, configured through the usual libpq
#     environment variables (PGHOST, PGPORT, PGDATABASE, PGUSER, ...).
#
# Usage
#   bash demo.sh                  # run against the server in PG* env vars
#   PG_BINDIR=/opt/pg19/bin bash demo.sh --temp-cluster
#                                 # initdb + start a throw-away cluster,
#                                 # run the demo, stop and delete it
#   KEEP=1 bash demo.sh           # leave schema and roles behind to poke at
#
# The script is self-checking: each scenario prints the rows each role sees
# and then asserts the expected row counts.  Exit status is non-zero if any
# assertion fails.

set -euo pipefail

PSQL=${PSQL:-psql}
SCHEMA=pgl_rls_demo
TEMP_CLUSTER=0
FAILURES=0
CHECKS=0

for arg in "$@"; do
    case "$arg" in
        --temp-cluster) TEMP_CLUSTER=1 ;;
        -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    BOLD=$'\e[1m'; GREEN=$'\e[32m'; RED=$'\e[31m'; DIM=$'\e[2m'; RESET=$'\e[0m'
else
    BOLD=; GREEN=; RED=; DIM=; RESET=
fi

section() { printf '\n%s== %s ==%s\n' "$BOLD" "$*" "$RESET"; }
note()    { printf '%s%s%s\n' "$DIM" "$*" "$RESET"; }

# ---------------------------------------------------------------------------
# psql helpers.  All statements run in the superuser session; per-role
# behaviour is obtained with SET ROLE, so no passwords or pg_hba changes are
# needed.  RLS policies see the role set by SET ROLE as current_user.
# ---------------------------------------------------------------------------
export PGOPTIONS="-c search_path=${SCHEMA},public ${PGOPTIONS:-}"

# run_sql <<'SQL' ... SQL   - execute a script, stop on first error
run_sql() { "$PSQL" -X -q -v ON_ERROR_STOP=1; }

# show <role> <sql>         - pretty-print the rows the role sees
show() {
    local role=$1 sql=$2
    printf '%s-- as %s:%s\n' "$DIM" "$role" "$RESET"
    "$PSQL" -X -q -v ON_ERROR_STOP=1 <<SQL
SET ROLE $role;
$sql
SQL
}

# count_as <role> <sql>     - number of rows the role sees
count_as() {
    local role=$1 sql=$2
    "$PSQL" -X -q -A -t -v ON_ERROR_STOP=1 <<SQL
SET ROLE $role;
SELECT count(*) FROM ($sql) AS rows_seen;
SQL
}

# check <label> <role> <expected> <sql>
check() {
    local label=$1 role=$2 expected=$3 sql=$4 actual
    CHECKS=$((CHECKS + 1))
    actual=$(count_as "$role" "$sql" | tr -d '[:space:]')
    if [ "$actual" = "$expected" ]; then
        printf '%sPASS%s %-9s %-52s rows=%s\n' "$GREEN" "$RESET" "$role" "$label" "$actual"
    else
        FAILURES=$((FAILURES + 1))
        printf '%sFAIL%s %-9s %-52s expected=%s actual=%s\n' \
            "$RED" "$RESET" "$role" "$label" "$expected" "$actual"
    fi
}

# ---------------------------------------------------------------------------
# Optional throw-away cluster
# ---------------------------------------------------------------------------
TMPDIR_CLUSTER=
cleanup_cluster() {
    if [ -n "$TMPDIR_CLUSTER" ]; then
        "$PG_BINDIR/pg_ctl" -D "$TMPDIR_CLUSTER/data" -m fast stop >/dev/null 2>&1 || true
        rm -rf "$TMPDIR_CLUSTER"
    fi
}

if [ "$TEMP_CLUSTER" = 1 ]; then
    : "${PG_BINDIR:?--temp-cluster needs PG_BINDIR=/path/to/pg19/bin}"
    PSQL="$PG_BINDIR/psql"
    TMPDIR_CLUSTER=$(mktemp -d)
    trap cleanup_cluster EXIT
    note "initdb into $TMPDIR_CLUSTER/data"
    "$PG_BINDIR/initdb" -D "$TMPDIR_CLUSTER/data" -A trust -U postgres \
        >"$TMPDIR_CLUSTER/initdb.log" 2>&1
    # Unix-socket only: no TCP port to collide with.
    "$PG_BINDIR/pg_ctl" -D "$TMPDIR_CLUSTER/data" -w \
        -o "-c listen_addresses='' -k '$TMPDIR_CLUSTER' -p 54329" \
        -l "$TMPDIR_CLUSTER/postgres.log" start >/dev/null
    export PGHOST=$TMPDIR_CLUSTER PGPORT=54329 PGUSER=postgres PGDATABASE=postgres
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
section "Preflight"
server_version=$("$PSQL" -X -A -t -c 'SHOW server_version_num' | tr -d '[:space:]')
if [ "${server_version:-0}" -lt 190000 ]; then
    echo "This demo needs PostgreSQL 19 or newer (GRAPH_TABLE); server reports $server_version" >&2
    exit 1
fi
is_super=$("$PSQL" -X -A -t -c 'SELECT rolsuper FROM pg_roles WHERE rolname = current_user' | tr -d '[:space:]')
if [ "$is_super" != "t" ]; then
    echo "This demo must connect as a superuser (it creates roles)" >&2
    exit 1
fi
note "server_version_num=$server_version, connected as superuser $("$PSQL" -X -A -t -c 'SELECT current_user')"

# ---------------------------------------------------------------------------
# Schema: element tables, the access-control model, and the property graph
# ---------------------------------------------------------------------------
section "Create roles, tables, policies and property graph"
run_sql <<SQL
SET client_min_messages TO warning;
DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE;
DROP ROLE IF EXISTS pgl_alice, pgl_bob, pgl_carol;
RESET client_min_messages;

CREATE ROLE pgl_alice NOLOGIN;   -- clearance 1, no compartments
CREATE ROLE pgl_bob   NOLOGIN;   -- clearance 2, compartment alpha
CREATE ROLE pgl_carol NOLOGIN;   -- clearance 3, compartments alpha + beta

CREATE SCHEMA ${SCHEMA};
SET search_path = ${SCHEMA}, public;

-- Every element table carries the two access-control properties.
CREATE TABLE person (
    id           int PRIMARY KEY,
    name         text NOT NULL,
    clevel       int NOT NULL DEFAULT 1,
    compartments text[] NOT NULL DEFAULT '{}'
);

CREATE TABLE company (
    id           int PRIMARY KEY,
    name         text NOT NULL,
    clevel       int NOT NULL DEFAULT 1,
    compartments text[] NOT NULL DEFAULT '{}',
    shared_with  name[] NOT NULL DEFAULT '{}'   -- explicit ACL, see policy below
);

CREATE TABLE knows (
    id           int PRIMARY KEY,
    src          int NOT NULL REFERENCES person (id),
    dst          int NOT NULL REFERENCES person (id),
    clevel       int NOT NULL DEFAULT 1,
    compartments text[] NOT NULL DEFAULT '{}'
);

CREATE TABLE works_at (
    id           int PRIMARY KEY,
    person_id    int NOT NULL REFERENCES person (id),
    company_id   int NOT NULL REFERENCES company (id),
    title        text,
    clevel       int NOT NULL DEFAULT 1,
    compartments text[] NOT NULL DEFAULT '{}'
);

-- Who is cleared for what.  Only the owner (superuser) can read this table;
-- readers get at it through the SECURITY DEFINER function below.
CREATE TABLE clearance (
    role_name    name PRIMARY KEY,
    clevel       int NOT NULL,
    compartments text[] NOT NULL DEFAULT '{}'
);
INSERT INTO clearance VALUES
    ('pgl_alice', 1, '{}'),
    ('pgl_bob',   2, '{alpha}'),
    ('pgl_carol', 3, '{alpha,beta}');

-- The whole access rule in one place.  current_user is passed in explicitly
-- because inside a SECURITY DEFINER function current_user is the definer.
CREATE FUNCTION can_access(who name, required_level int, required_compartments text[])
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ${SCHEMA}, pg_temp
AS \$\$
    SELECT EXISTS (
        SELECT 1
          FROM clearance c
         WHERE c.role_name = who
           AND c.clevel >= required_level
           AND required_compartments <@ c.compartments);
\$\$;

-- ---- Row-level policies = node- and relationship-level security ----------
ALTER TABLE person   ENABLE ROW LEVEL SECURITY;
ALTER TABLE company  ENABLE ROW LEVEL SECURITY;
ALTER TABLE knows    ENABLE ROW LEVEL SECURITY;
ALTER TABLE works_at ENABLE ROW LEVEL SECURITY;

CREATE POLICY node_visible ON person   FOR SELECT
    USING (can_access(current_user, clevel, compartments));
CREATE POLICY edge_visible ON knows    FOR SELECT
    USING (can_access(current_user, clevel, compartments));
CREATE POLICY edge_visible ON works_at FOR SELECT
    USING (can_access(current_user, clevel, compartments));

-- Two PERMISSIVE policies are OR-ed: a company is visible if the reader is
-- cleared for it, OR it has been explicitly shared with the reader.
CREATE POLICY node_visible ON company  FOR SELECT
    USING (can_access(current_user, clevel, compartments));
CREATE POLICY node_shared  ON company  FOR SELECT
    USING (current_user = ANY (shared_with));

-- ---- Data ---------------------------------------------------------------
INSERT INTO person VALUES
    (1, 'Ada',      1, '{}'),
    (2, 'Grace',    2, '{alpha}'),
    (3, 'Linus',    1, '{}'),
    (4, 'Margaret', 3, '{alpha,beta}'),
    (5, 'Ken',      2, '{}');

INSERT INTO company VALUES
    (10, 'Acme',       1, '{}',      '{}'),
    (20, 'Skunkworks', 2, '{alpha}', '{}'),
    (30, 'BlackSite',  3, '{beta}',  '{pgl_alice}');   -- shared with alice

INSERT INTO knows VALUES
    (100, 1, 2, 1, '{}'),       -- Ada      -> Grace
    (101, 2, 3, 1, '{}'),       -- Grace    -> Linus
    (102, 1, 3, 1, '{}'),       -- Ada      -> Linus
    (103, 3, 4, 1, '{}'),       -- Linus    -> Margaret
    (104, 4, 5, 1, '{}'),       -- Margaret -> Ken
    (105, 1, 5, 1, '{alpha}');  -- Ada      -> Ken       (edge needs alpha)

INSERT INTO works_at VALUES
    (200, 1, 10, 'engineer',  1, '{}'),
    (201, 2, 20, 'lead',      1, '{}'),
    (202, 3, 10, 'engineer',  1, '{}'),
    (203, 4, 30, 'director',  1, '{}'),
    (204, 5, 10, 'advisor',   3, '{}');   -- edge itself is classified level 3

-- ---- The property graph -------------------------------------------------
CREATE PROPERTY GRAPH social
    VERTEX TABLES (
        person  KEY (id),
        company KEY (id)
    )
    EDGE TABLES (
        knows KEY (id)
            SOURCE      KEY (src) REFERENCES person (id)
            DESTINATION KEY (dst) REFERENCES person (id),
        works_at KEY (id)
            SOURCE      KEY (person_id)  REFERENCES person (id)
            DESTINATION KEY (company_id) REFERENCES company (id)
    );

-- Readers need privileges on the graph AND on the element tables: the base
-- relations are accessed with the querying user's privileges, not the graph
-- owner's (see CREATE PROPERTY GRAPH, Notes).
GRANT USAGE ON SCHEMA ${SCHEMA} TO pgl_alice, pgl_bob, pgl_carol;
GRANT SELECT ON person, company, knows, works_at TO pgl_alice, pgl_bob, pgl_carol;
GRANT SELECT ON PROPERTY GRAPH social TO pgl_alice, pgl_bob, pgl_carol;
-- clearance stays owner-only; can_access() is the only way in.
REVOKE ALL ON clearance FROM PUBLIC;
SQL
note "clearances: alice=1/{}  bob=2/{alpha}  carol=3/{alpha,beta}"

# ---------------------------------------------------------------------------
# Scenario 1: node-level security
# ---------------------------------------------------------------------------
section "1. Node-level security: (p IS person)"
Q1="SELECT * FROM GRAPH_TABLE (social
        MATCH (p IS person)
        COLUMNS (p.name, p.clevel, p.compartments)) ORDER BY 1"
show pgl_alice "$Q1"
show pgl_bob   "$Q1"
show pgl_carol "$Q1"
check "person nodes"   pgl_alice 2 "$Q1"   # Ada, Linus
check "person nodes"   pgl_bob   4 "$Q1"   # + Grace, Ken
check "person nodes"   pgl_carol 5 "$Q1"

section "1b. Two PERMISSIVE policies OR together: (c IS company)"
Q1b="SELECT * FROM GRAPH_TABLE (social
        MATCH (c IS company)
        COLUMNS (c.name, c.clevel, c.compartments, c.shared_with)) ORDER BY 1"
show pgl_alice "$Q1b"
show pgl_bob   "$Q1b"
check "company nodes"  pgl_alice 2 "$Q1b"  # Acme + BlackSite (shared_with)
check "company nodes"  pgl_bob   2 "$Q1b"  # Acme + Skunkworks
check "company nodes"  pgl_carol 3 "$Q1b"

# ---------------------------------------------------------------------------
# Scenario 2: relationship-level security
# ---------------------------------------------------------------------------
section "2. Relationship-level security: (a)-[k IS knows]->(b)"
note "Edge 105 Ada->Ken requires compartment alpha although both endpoints"
note "are visible to bob; alice cannot see Ken at all."
Q2="SELECT * FROM GRAPH_TABLE (social
        MATCH (a IS person)-[k IS knows]->(b IS person)
        COLUMNS (k.id AS edge, a.name AS src, b.name AS dst, k.compartments)) ORDER BY 1"
show pgl_alice "$Q2"
show pgl_bob   "$Q2"
show pgl_carol "$Q2"
check "knows edges"    pgl_alice 1 "$Q2"   # 102 Ada->Linus
check "knows edges"    pgl_bob   4 "$Q2"   # 100 101 102 105
check "knows edges"    pgl_carol 6 "$Q2"

section "2b. Edge classified higher than both endpoints: (p)-[w IS works_at]->(c)"
note "Edge 204 (Ken advises Acme) is level 3; bob sees Ken and Acme but not"
note "the relationship between them."
Q2b="SELECT * FROM GRAPH_TABLE (social
        MATCH (p IS person)-[w IS works_at]->(c IS company)
        COLUMNS (w.id AS edge, p.name AS person, w.title, c.name AS company, w.clevel)) ORDER BY 1"
show pgl_bob   "$Q2b"
show pgl_carol "$Q2b"
check "works_at edges" pgl_alice 2 "$Q2b"  # 200 202
check "works_at edges" pgl_bob   3 "$Q2b"  # 200 201 202
check "works_at edges" pgl_carol 5 "$Q2b"

# ---------------------------------------------------------------------------
# Scenario 3: cannot query *through* a hidden node
# ---------------------------------------------------------------------------
section "3. Query-through: (a)-[]->(b)-[]->(c) with a hidden middle node"
note "alice sees Ada and Linus and the direct edge Ada->Linus, but the 2-hop"
note "path Ada->Grace->Linus is invisible because Grace (level 2) is hidden."
Q3="SELECT * FROM GRAPH_TABLE (social
        MATCH (a IS person)-[IS knows]->(b IS person)-[IS knows]->(c IS person)
        COLUMNS (a.name AS start, b.name AS via, c.name AS finish)) ORDER BY 1, 2, 3"
show pgl_alice "$Q3"
show pgl_bob   "$Q3"
show pgl_carol "$Q3"
check "2-hop paths"    pgl_alice 0 "$Q3"
check "2-hop paths"    pgl_bob   1 "$Q3"   # Ada->Grace->Linus
check "2-hop paths"    pgl_carol 4 "$Q3"

section "3b. Colleagues-of-colleagues through an edge alone"
note "(a)-[works_at]->(c)<-[works_at]-(b): both endpoints and the company are"
note "visible to bob, yet Ken never appears because edge 204 is level 3."
Q3b="SELECT * FROM GRAPH_TABLE (social
        MATCH (a IS person)-[IS works_at]->(c IS company)<-[IS works_at]-(b IS person)
        WHERE a.id <> b.id
        COLUMNS (a.name AS a, c.name AS company, b.name AS b)) ORDER BY 1, 2, 3"
show pgl_bob   "$Q3b"
show pgl_carol "$Q3b"
check "colleague pairs" pgl_alice 2 "$Q3b"  # Ada/Linus both ways
check "colleague pairs" pgl_bob   2 "$Q3b"  # Ada/Linus both ways (no Ken)
check "colleague pairs" pgl_carol 6 "$Q3b"  # Ada/Linus/Ken all pairs

# ---------------------------------------------------------------------------
# Scenario 4: RESTRICTIVE policies narrow further, per role
# ---------------------------------------------------------------------------
section "4. RESTRICTIVE policy on top: bob may not traverse alpha-compartment edges"
run_sql <<SQL
CREATE POLICY bob_no_alpha_edges ON knows AS RESTRICTIVE FOR SELECT TO pgl_bob
    USING (NOT ('alpha' = ANY (compartments)));
SQL
show pgl_bob "$Q2"
check "knows edges (restricted)" pgl_bob   3 "$Q2"   # 105 gone
check "knows edges (unchanged)"  pgl_carol 6 "$Q2"
run_sql <<SQL
DROP POLICY bob_no_alpha_edges ON knows;
SQL

# ---------------------------------------------------------------------------
# Scenario 5: filters inside MATCH cannot leak hidden elements
# ---------------------------------------------------------------------------
section "5. WHERE inside MATCH runs after the security quals"
note "A non-LEAKPROOF function in the pattern's WHERE is only ever called on"
note "rows the policy already let through, so it cannot be used as an oracle."
run_sql <<SQL
CREATE FUNCTION spy(text) RETURNS boolean
    LANGUAGE plpgsql COST 0.0000001
    AS \$\$ BEGIN RAISE NOTICE 'spy saw %', \$1; RETURN true; END \$\$;
GRANT EXECUTE ON FUNCTION spy(text) TO pgl_alice;
SQL
Q5="SELECT * FROM GRAPH_TABLE (social
        MATCH (p IS person WHERE spy(p.name))
        COLUMNS (p.name)) ORDER BY 1"
show pgl_alice "$Q5"
check "rows visible through spy()" pgl_alice 2 "$Q5"
spy_output=$("$PSQL" -X -q -v ON_ERROR_STOP=1 <<SQL 2>&1
SET ROLE pgl_alice;
$Q5
SQL
)
spied=$(grep -c 'spy saw' <<<"$spy_output" || true)
CHECKS=$((CHECKS + 1))
if [ "$spied" = 2 ]; then
    printf '%sPASS%s %-9s %-52s notices=%s\n' "$GREEN" "$RESET" pgl_alice "spy() called only for visible rows" "$spied"
else
    FAILURES=$((FAILURES + 1))
    printf '%sFAIL%s %-9s %-52s expected=2 notices=%s\n' "$RED" "$RESET" pgl_alice "spy() called only for visible rows" "$spied"
fi

# ---------------------------------------------------------------------------
# Scenario 6: what bypasses RLS, and what row_security=off does
# ---------------------------------------------------------------------------
section "6. Superusers / owners bypass; ordinary users cannot switch RLS off"
superuser=$("$PSQL" -X -A -t -c 'SELECT current_user' | tr -d '[:space:]')
note "The table owner (here the superuser) is not subject to the policies unless"
note "ALTER TABLE ... FORCE ROW LEVEL SECURITY is used."
show "$superuser" "$Q2"
check "knows edges as superuser" "$superuser" 6 "$Q2"
CHECKS=$((CHECKS + 1))
if out=$("$PSQL" -X -q -v ON_ERROR_STOP=1 <<SQL 2>&1
SET ROLE pgl_bob;
SET row_security = off;
$Q2
SQL
); then
    FAILURES=$((FAILURES + 1))
    printf '%sFAIL%s %-9s %-52s (query succeeded)\n' "$RED" "$RESET" pgl_bob "row_security=off is rejected"
else
    if grep -q 'row-level security' <<<"$out"; then
        printf '%sPASS%s %-9s %-52s %s\n' "$GREEN" "$RESET" pgl_bob "row_security=off is rejected" \
            "$(grep -o 'ERROR:.*' <<<"$out" | head -1)"
    else
        FAILURES=$((FAILURES + 1))
        printf '%sFAIL%s %-9s %-52s unexpected error: %s\n' "$RED" "$RESET" pgl_bob "row_security=off is rejected" "$out"
    fi
fi

# ---------------------------------------------------------------------------
# Scenario 7: look at the plan
# ---------------------------------------------------------------------------
section "7. EXPLAIN: the policy is applied on every element scan of the path"
show pgl_bob "EXPLAIN (COSTS OFF)
$Q3"

# ---------------------------------------------------------------------------
# Summary and cleanup
# ---------------------------------------------------------------------------
section "Summary"
printf '%d checks, %d failures\n' "$CHECKS" "$FAILURES"

if [ "${KEEP:-0}" != 1 ]; then
    run_sql <<SQL
SET client_min_messages TO warning;
DROP SCHEMA ${SCHEMA} CASCADE;
DROP ROLE pgl_alice, pgl_bob, pgl_carol;
SQL
    note "cleaned up schema ${SCHEMA} and demo roles (set KEEP=1 to keep them)"
else
    note "kept schema ${SCHEMA} and demo roles"
fi

[ "$FAILURES" -eq 0 ]
