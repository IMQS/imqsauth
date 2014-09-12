IMQS Authentication/Authorization
=================================
This contains the IMQS specializations on top of the generic
authaus system.

## TODO

* More logging
* Log rotation
* Add a 'rekey' command which generates a new password for all of the postgres databases
  specified in the config file, executes the appropriate password change on the database
  itself, and writes the modified config back to the config file.
