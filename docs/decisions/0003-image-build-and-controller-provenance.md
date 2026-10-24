# 0003: Preserve build and qualification-controller provenance separately

WORM-005 image assembly and SSH qualification are distinct operations. A fix to
the host controller need not change the seven recipe files installed or used in
the images. Requiring an identical whole-repository revision would force a rebuild
without establishing a stronger relationship between unchanged recipe bytes.

Keep exact clean-source enforcement for each assembly. Qualification validates
each original build Run and its completed reconciled schema1.0 assembly receipt,
including the original canonical source revision. It then requires every recipe
file hash and combined recipe identity to equal the current clean controller's
recipe. Actual immutable image identity, linux/amd64 platform, no declared volumes
and original source/run/role/recipe labels must agree. Changing controller code
does not authorize relabeling an image or accepting a changed recipe.

Qualification records its own source revision alongside separate target/helper
build source revisions and the shared recipe hashes. Thus target A/helper B can be
tested by controller C without claiming either image was built by C. This decision
does not grant acceptance, establish SSH success, permit dirty builds, change the
assembly procedure or extend runtime-pipeline eligibility.
