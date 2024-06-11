# List and Diff tool for IMQS Groups and Permissions

This tool is used to compare the groups and permissions in two different
environments. It will list the groups and permissions that are in the source
environment but not in the target environment, and vice versa.

As config it takes a modified `imqsauth.json` and a modified version of the
/groups_perm_names in `imqsauth2.json`.

As cmd line inputs it takes _n_ filenames of the 'json' group exports of Auth
from IMQS V8 User Management and compares them with each other.

Typical usage:

```bash
./listanddiff AuthProd.json AuthPreProd.json AuthQA.json
```

The output will be a de-normalised csv file for each of the input files, with
columns for e.g. `Group`, `PermName`, `PermId`. This can be used to compare with an external
reference for the groups and the permissions they should contain.

The comparison file, `output.csv`, will contain the following columns:
- GroupName
- PermissionId
- PermissionName
- Comment

The comment fields should mention context and target that does not have the group or permission.
Groups entries will only have the group name and the comment field.

