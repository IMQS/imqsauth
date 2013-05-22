/*
Package imqsauth implements a service that answers various authentication and authorization questions.

'imqsauth' is built on top of Authaus, which is a generic authentication and authorization package.

Authaus has the notion of a 'permit', which is a binary blob. We interpret this in the following
way: Every 32-bit word in the permit is an index into the 'authgroups' table.

The 'authgroups' table looks like this:

  id (int32) | name (txt) | permbits (binary)

So each 32-bit word in the 'permit' refers to one record from that table.
The 'name' of the group is merely for display purposes. Without it, people
wouldn't be able to remember which group was which. The important part is
the 'permbits'. This a list of 16-bit integers. Each 16-bit integer in this
list activates a certain permission, such as "Verify assets", or 
"View electricity lines".

There may come a day when we need data-dependent permissions, such as 
"Allowed to edit assets with ID = 3017". These kinds of permissions
cannot be hard-coded into the application, so they don't fit into
this scheme. However, it should not be too difficult to expand this
system to accomodate that kind of thing.

*/
package imqsauth
