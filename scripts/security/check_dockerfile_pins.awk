# An earlier named stage is local to this Dockerfile; every external base
# retains the digest requirement. Never carry aliases across input files.
FNR == 1 {
    for (stage in stages) delete stages[stage]
}
toupper($1) == "FROM" {
    image = tolower($2)
    if ($2 !~ /@sha256:/ && !(image in stages)) {
        print FILENAME ":" FNR ": base image is not digest pinned: " $0
        invalid = 1
    }
    # Register only after validating FROM, rejecting self/forward references.
    if (toupper($3) == "AS" && NF >= 4) stages[tolower($4)] = 1
}
END { exit invalid }
