// Configuration options
{
	// Default encoding for text
	"info" : {
		"description" : "shows time, user and file name for every read or write operation that is performed in the specified directory",
		"arguments" : [ 
			{"name" : "dirname", "description" : "the directory name. specifying a directory, for example /etc/ will match all the files in it recursively.", "type" : "string"}
		]
    },
	"chisels" : [ 
		{
			"filter" : "fd.name contains $dirname",
			"format" : "time:%evt.time user:%user.name process:%proc.name file:%fd.name"
		}
	]
}