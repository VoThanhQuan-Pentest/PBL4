# Entity Implementation Rules

Apply these rules when writing or modifying any JPA entity. All rules assume the conventions resolved in Step 1 are already applied.

---

## Class — creating a new entity class

- Annotate with `@Entity`
- If naming strategy = explicit (Step 1.5) — add `@Table(name = "...")` with the name derived from the table name template convention
- If naming strategy = implicit — add `@Table` without `name`
- If Lombok = yes (Step 1.5) — add Lombok annotations on the class according to resolved Lombok conventions:
  - Add `@Getter` and/or `@Setter` if configured
  - If `@AllArgsConstructor` is configured — add it
  - If `@NoArgsConstructor` is configured — add it
  - If `@Builder` is configured — add it; `@Builder` requires both `@AllArgsConstructor` and `@NoArgsConstructor` to be present (JPA needs the no-args constructor, Builder generates the all-args one)
- If Lombok = no — no Lombok annotations; write getters and setters manually

---

## Id

Every entity must have an `id` field — either declared directly or inherited from a parent class. Before adding `id` to an entity, call `get_entity_details` to check if the parent already provides it.

If `id` must be declared directly:

**Database-generated (SEQUENCE)** — declare `private Long id` with the following annotations:

- Annotate with `@Id`
- Annotate with `@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "<name>")`
- If sequence scope = dedicated per table — also annotate with `@SequenceGenerator(name = "<name>")` using an entity-specific name (e.g. `loan_seq`)
- If sequence scope = shared — also annotate with `@SequenceGenerator(name = "<shared_name>")` using the shared name found in existing entities
- If sequence scope = Hibernate default — omit `@SequenceGenerator`
- If naming strategy = explicit — annotate with `@Column(name = "id", nullable = false)`
- If naming strategy = implicit — annotate with `@Column(nullable = false)`

**Database-generated (IDENTITY)** — declare `private Long id` with the following annotations:

- Annotate with `@Id`
- Annotate with `@GeneratedValue(strategy = GenerationType.IDENTITY)`
- If naming strategy = explicit — annotate with `@Column(name = "id", nullable = false)`
- If naming strategy = implicit — annotate with `@Column(nullable = false)`

**Client-generated** — declare `private UUID id` with the following annotations:

- Annotate with `@Id`
- Annotate with `@GeneratedValue(strategy = GenerationType.UUID)`
- If naming strategy = explicit — annotate with `@Column(name = "id", nullable = false)`
- If naming strategy = implicit — annotate with `@Column(nullable = false)`

---

## Field Annotation Rules

Every field must have `@Column` with explicit `name`:

```java
// CORRECT
@Column(name = "birth_date")
private LocalDate birthDate;

// WRONG — missing explicit column name
private LocalDate birthDate;
```

**Validation** — use bean validation (Jakarta Validation) for all field constraints.

---

## Field Type Rules

### BigDecimal

`BigDecimal` must always be declared with explicit `precision` and `scale` in `@Column` — without them Hibernate uses database defaults which vary across vendors and cause precision loss:

```java
// CORRECT
@Column(name = "price", precision = 10, scale = 2)
private BigDecimal price;

// WRONG — missing precision and scale
@Column(name = "price")
private BigDecimal price;
```

---

## Relationship Rules

### OneToMany

Prefer **bidirectional** `@OneToMany` over unidirectional — unidirectional requires an extra join table or produces inefficient SQL (extra DELETE + INSERT on collection changes). In a bidirectional relationship, the `@ManyToOne` side owns the FK column:

Use `Set<>` initialized as `LinkedHashSet` (preserves insertion order) as the default collection type — in this case the child entity must have correct `equals`/`hashCode` (see section below). If `List` is used instead, `equals`/`hashCode` on the child side are not required.

```java
// Parent side
@OneToMany(mappedBy = "owner", fetch = FetchType.LAZY)
@OrderBy("name")
private Set<Pet> pets = new LinkedHashSet<>();

// Child side owns the FK
@ManyToOne
@JoinColumn(name = "owner_id")
private Owner owner;
```

### ManyToOne

```java
@ManyToOne(fetch = FetchType.LAZY)
@JoinColumn(name = "owner_id")
private Owner owner;
```

- No cascade on ManyToOne (reference to existing data)
- Always specify `@JoinColumn(name = "...")` explicitly
- `FetchType.LAZY` by default — override to `EAGER` only when explicitly needed

### ManyToMany

```java
@ManyToMany
@JoinTable(
    name = "vet_specialties",
    joinColumns = @JoinColumn(name = "vet_id"),
    inverseJoinColumns = @JoinColumn(name = "specialty_id")
)
private Set<Specialty> specialties;
```

- Always use `Set` for ManyToMany collections — using `List` is strongly discouraged because Hibernate deletes and reinserts all rows on every change (the "bag" problem); use `List` only as a last resort
- Always define `@JoinTable` with explicit table name and both join columns
- The inverse side entity must have `equals`/`hashCode` — `Set` requires them for correct behavior (see section below)

---

## equals & hashCode

Never include relation fields (`@ManyToOne`, `@OneToMany`, `@ManyToMany`, `@OneToOne`) in `equals`/`hashCode` — accessing them triggers lazy loading and causes `LazyInitializationException` outside a transaction. Only include relation fields if the user explicitly requests it.

If equals/hashCode style = manual (Step 1.5) — implement the proxy-safe pattern that compares effective classes rather than direct `instanceof`:

If equals/hashCode style = Lombok (Step 1.5):

- Annotate the class with `@EqualsAndHashCode(onlyExplicitlyIncluded = true)`
- Annotate the `id` field (or the fields resolved in Step 1.5) with `@EqualsAndHashCode.Include`
- Do not add `@EqualsAndHashCode.Include` to any relation fields

**Manual pattern** — correctly handles uninitialized proxies:

```java
@Override
public final boolean equals(Object o) {
    if (this == o) return true;
    if (o == null) return false;
    Class<?> objectEffectiveClass = o instanceof HibernateProxy proxy
        ? proxy.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
    Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy
        ? proxy.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
    if (thisEffectiveClass != objectEffectiveClass) return false;
    Pet other = (Pet) o;
    return getId() != null && Objects.equals(getId(), other.getId());
}

@Override
public final int hashCode() {
    return this instanceof HibernateProxy proxy
        ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
        : getClass().hashCode();
}
```

---

## toString

Never include relation fields (`@ManyToOne`, `@OneToMany`, `@ManyToMany`, `@OneToOne`) in `toString()` — accessing them triggers lazy loading and causes `LazyInitializationException` outside a transaction. Only include relation fields if the user explicitly requests it.

If toString style = manual (Step 1.5):

- Override `toString()` and include only local (non-relation) fields according to the toString fields convention from Step 1.5

If toString style = Lombok (Step 1.5):

- If `@ToString(onlyExplicitlyIncluded = true)` is configured — annotate the class with `@ToString(onlyExplicitlyIncluded = true)` and annotate each included local field with `@ToString.Include`
- Otherwise — annotate the class with `@ToString` and annotate each relation field with `@ToString.Exclude` to prevent lazy loading

**Manual pattern** — only local fields: