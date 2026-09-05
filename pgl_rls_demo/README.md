# Node- and relationship-level security for SQL/PGQ with row-level policies

This directory evaluates whether PostgreSQL 19's property graph support
(SQL/PGQ, `CREATE PROPERTY GRAPH` + `GRAPH_TABLE`) can be combined with
row-level security (RLS) to give fine-grained, per-user access control over
individual nodes and edges. `demo.sh` is a self-checking bash script that
builds the pattern end to end.

**Short answer: yes, and it needs no new server code.** A property graph is a
read-only view over ordinary tables. `GRAPH_TABLE` is rewritten into a plain
`SELECT` over the vertex and edge tables *before* RLS is applied, so any policy
on an element table filters the graph automatically:

* a node whose row the policy hides cannot be returned by any pattern;
* an edge whose row is hidden cannot be traversed, even when both of its
  endpoints are visible;
* a path cannot be "queried through" a hidden intermediate node or edge, because
  the path is a join and the hidden row is simply not there to join to.

## What the server does

`GRAPH_TABLE` is handled entirely in the rewriter. In
`src/backend/rewrite/rewriteHandler.c`, `fireRIRrules()` calls
`rewriteGraphTable()` for each `RTE_GRAPH_TABLE` range-table entry, which turns
the entry into an `RTE_SUBQUERY` whose body is a `UNION` of one join query per
matching path (`src/backend/rewrite/rewriteGraphTable.c`,
`generate_query_for_graph_path()`). Each vertex or edge in a path becomes a
normal `RTE_RELATION` for its element table, added with the *current user's*
privileges (a comment there notes this is deliberate, "in line with the views
being security_invoker by default").

Immediately afterwards the rewriter recurses into that new subquery with
`fireRIRrules()`, and the ordinary RLS pass (`get_row_security_policies()`)
attaches `securityQuals` to each of those element-table entries, exactly as it
would for a hand-written join. The generated subquery is also marked `LATERAL`
and the enclosing query inherits `hasRowSecurity`, so prepared statements are
re-planned when the user or policy set changes.

The reference documentation says the same thing from the user's side
(`doc/src/sgml/ref/create_property_graph.sgml`, Notes):

> Access to the base relations underlying the `GRAPH_TABLE` clause is
> determined by the permissions of the user executing the query, rather than
> the property graph owner. Thus, the user of a property graph must have the
> relevant permissions on the property graph and base relations underlying the
> `GRAPH_TABLE` clause.

There is also a dedicated regression test, `src/test/regress/sql/graph_table_rls.sql`
(scheduled in `parallel_schedule`), that exercises PERMISSIVE and RESTRICTIVE
policies, role-targeted policies, policies on inherited and partitioned
element tables, `FORCE ROW LEVEL SECURITY`, `BYPASSRLS`, `row_security = off`,
leaky functions inside `MATCH ... WHERE`, and recursion detection when a policy
itself uses `GRAPH_TABLE` on the table it protects.

The public page `https://www.postgresql.org/docs/19/queries-graph.html` is
built from the same SGML sources that live in this tree
(`doc/src/sgml/queries.sgml`, section `queries-graph`, and
`doc/src/sgml/ddl.sgml`, section `ddl-property-graphs`). Neither page mentions
RLS at all; the interaction falls out of the design rather than being a
documented feature.

## The pattern

Every element table carries the security properties you want to evaluate; the
demo uses a classification level and a set of compartments:

```sql
CREATE TABLE person (
    id           int PRIMARY KEY,
    name         text NOT NULL,
    clevel       int NOT NULL DEFAULT 1,
    compartments text[] NOT NULL DEFAULT '{}'
);
-- same two columns on company, knows (person->person) and works_at (person->company)
```

The access rule lives in one `STABLE SECURITY DEFINER` function that reads a
private clearance table, and each element table gets one policy calling it:

```sql
CREATE FUNCTION can_access(who name, required_level int, required_compartments text[])
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pgl_rls_demo, pg_temp
AS $$ SELECT EXISTS (SELECT 1 FROM clearance c
                      WHERE c.role_name = who
                        AND c.clevel >= required_level
                        AND required_compartments <@ c.compartments) $$;

ALTER TABLE person ENABLE ROW LEVEL SECURITY;
CREATE POLICY node_visible ON person FOR SELECT
    USING (can_access(current_user, clevel, compartments));
-- identical policies on company, knows, works_at
```

The graph itself is unremarkable:

```sql
CREATE PROPERTY GRAPH social
    VERTEX TABLES (person KEY (id), company KEY (id))
    EDGE TABLES (
        knows KEY (id)
            SOURCE KEY (src) REFERENCES person (id)
            DESTINATION KEY (dst) REFERENCES person (id),
        works_at KEY (id)
            SOURCE KEY (person_id) REFERENCES person (id)
            DESTINATION KEY (company_id) REFERENCES company (id));

GRANT SELECT ON person, company, knows, works_at TO pgl_alice, pgl_bob, pgl_carol;
GRANT SELECT ON PROPERTY GRAPH social TO pgl_alice, pgl_bob, pgl_carol;
```

Readers need `SELECT` on both the graph and the element tables. They do not
need to read the clearance table; the function does that for them.

## What the demo shows

| Scenario | Query shape | Point demonstrated |
| --- | --- | --- |
| 1 | `(p IS person)` | node-level filtering per role |
| 1b | `(c IS company)` | two PERMISSIVE policies are OR-ed (clearance *or* explicit `shared_with` ACL) |
| 2 | `(a)-[k IS knows]->(b)` | an edge needing a compartment is hidden even though both endpoints are visible |
| 2b | `(p)-[w IS works_at]->(c)` | an edge classified higher than its endpoints disappears |
| 3 | `(a)-[]->(b)-[]->(c)` | no querying through a hidden middle node (alice sees Ada, Linus and Ada->Linus, but not Ada->Grace->Linus) |
| 3b | `(a)-[]->(c)<-[]-(b)` | no querying through a hidden edge |
| 4 | RESTRICTIVE policy `TO pgl_bob` | per-role narrowing on top of the base rule |
| 5 | `(p WHERE spy(p.name))` | a non-leakproof function in `MATCH ... WHERE` only ever sees rows the policy admitted |
| 6 | superuser / `SET row_security = off` | owners and superusers bypass; ordinary users get an error instead of unfiltered data |
| 7 | `EXPLAIN` | the policy qual appears as a filter on every element scan of the path |

Each scenario prints what each role sees and asserts the row count, so the
script doubles as a regression check for the pattern.

## Running it

```bash
# against a running PostgreSQL 19, connecting as a superuser
PGHOST=localhost PGPORT=5432 PGUSER=postgres bash pgl_rls_demo/demo.sh

# or with a throw-away cluster from a build tree
PG_BINDIR=/path/to/pg19/bin bash pgl_rls_demo/demo.sh --temp-cluster

# keep the schema and roles around afterwards
KEEP=1 bash pgl_rls_demo/demo.sh
```

The script refuses to run against a server older than 19 or as a
non-superuser (it creates three `NOLOGIN` roles and uses `SET ROLE`, so no
passwords or `pg_hba.conf` changes are needed).

To build a server from this tree: `./configure && make -j && make install`,
then use `<prefix>/bin` as `PG_BINDIR`. The regression test that covers the
same ground can be run with `make check-tests TESTS=graph_table_rls`.

## Things to keep in mind when designing on this

* **Policies attach to tables, not to labels or the graph.** If two labels
  share a table, they share the policy. If you want different rules per label,
  put the labels on different tables (or use a discriminator column in the
  policy).
* **Properties defined as expressions are not policy targets.** A policy can
  only reference the table's columns, but it can repeat the same expression.
* **Only `SELECT` matters.** `GRAPH_TABLE` is read-only, so only `FOR SELECT`
  (or `FOR ALL`) policies apply. Writes go through the tables as usual.
* **The graph owner's privileges are irrelevant.** Unlike a `SECURITY DEFINER`
  view, a property graph never widens access. Users need `SELECT` on the
  element tables themselves. A `security_definer`-style graph would have to be
  built by pointing the graph at security-definer views instead of tables.
* **Owners and superusers bypass RLS** unless the table has
  `FORCE ROW LEVEL SECURITY`; roles with `BYPASSRLS` always bypass.
* **Performance.** The policy qual runs on every element scan in every
  generated path query, and a `STABLE` SQL function with a subselect is
  evaluated per row. For large graphs consider a `LEAKPROOF`-friendly
  formulation (e.g. resolve the user's clearance once per session into a GUC
  with `set_config` and compare columns against `current_setting(...)`), and
  make sure the policy expression can use indexes on the security columns.
  Non-leakproof functions in the user's `WHERE` are evaluated after the
  security quals, which can defeat index use on those user predicates.
* **No variable-length paths yet.** The docs in this tree still mark
  quantifiers and multiple comma-separated path patterns as TODO, so "reachable
  through any number of hops" has to be expressed with fixed-length patterns or
  a recursive CTE around `GRAPH_TABLE`. RLS applies the same way in both cases.
* **A policy may not (transitively) query its own table through the graph.**
  The rewriter detects this and raises "infinite recursion detected in policy".
