# List and Diff tool for IMQS Groups and Permissions

This tool is used to compare the groups and permissions in two different
environments. It will list the groups and permissions that are in the source
environment but not in the target environment, and vice versa.

## Config

The tool takes 2 types of configuration:

| Filename       | Description                                                             | Optional |
|----------------|-------------------------------------------------------------------------|----------|
| imqsauth.json  | The configuration file for the _source_ Auth service.                   | No       |
| imqsauth2.json | The configuration file for the _destination_ Auth service.              | No       |
| authmap.json   | The permissions as returned by the _source_ Auth service (modded).      | No       |
| authmap2.json  | The permissions as returned by the _destination_ Auth service (modded). | No       |

These files are used to look up the permission names from the permission
id's as extracted from the group permits.

The `imqsauthx.json` file structure should be exactly the same as the Auth 
service config, but only the **Permissions** section should be present 
(security). A drawback here is that it **won't** contain any static (older) 
permissions that exist in code.

The `authmapx.json` files should contain the full permission set (static + 
dynamic) of the relevant Auth service. It can be retrieved from the **source**
and **destination** Auth services by calling the `auth2/groups_perm_names` 
endpoint, and storing it as-is.

Technically the `authmapx.json` files should be sufficient, but the 
`imqsauthx.json` may 
be more convenient as the files exist in the configs already.

## Usage

**Input**

```bash
./listanddiff AuthProd.json AuthPreProd.json
```

As command line input the tool takes _n_ files as parameters.
The files should be JSON **group** exports from User Management in the source 
and target environments. All files are compared with each other.

The files are typically downloaded in zipped format and should be extracted
beforehand.

**Output**

The tool generates two types of output files:

| Filename           | Description                                                                               |
|--------------------|-------------------------------------------------------------------------------------------|
| <input_file_n>.csv | De-normalised reference file of the matching input file.                                  |
| output.csv         | The differential of the comparison of the groups and permissions in the two environments. |

`<input_file_n>.csv`

The output will be a de-normalised csv file for each of the input files, with
columns for e.g. `Group`, `PermName`, `PermId`. It can be used to compare with 
an external reference for the groups and the permissions, perhaps as specified 
by the client.

`output.csv`

The comparison file, `output.csv`, will contain the following columns:
- GroupName
- PermissionId
- PermissionName
- Comment

The comment fields should mention context and target that 
does not have the group or permission. The following 
scenarios are possible:
- _Unknown permissions_: The `PermissionName` field will be
    blank, as no lookup reference was found int he configs provided.
- _Matching groups, permissions differ_: All fields should be populated.
- _Missing groups_: Groups entries will only have the group name populated, 
    with context provided in the comment field.

## Future work

- Combine the tool with the scripts and function app in `azure-reference` for a
  more complete comparison and reporting tool.
- Add the ability to consume an excel / csv matrix of groups and permissions to
  compare against the environment exports.
