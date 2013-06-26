/*
Package imqsauth implements a service that answers various authentication and authorization questions.

'imqsauth' is built on top of Authaus, which is a generic authentication and authorization package.

There may come a day when we need data-dependent permissions, such as
"Allowed to edit assets with ID = 3017". These kinds of permissions
cannot be hard-coded into the application, so they don't fit into
this scheme. However, it should not be too difficult to expand this
system to accomodate that kind of thing.

*/
package imqsauth
