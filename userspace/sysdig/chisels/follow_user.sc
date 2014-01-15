// Configuration options
{
	// Default encoding for text
	"info" : {
		"description" : "lists every command that a specific user launches interactively (e.g. from bash) and every directory the user visits",
		"arguments" : [ 
			{"name" : "username", "type" : "string"}
		]
    },
	"chisels" : [ 
		{
			"filter" : "user.name=$username and evt.type=execve and proc.name!=bash and proc.parentname=bash",
			"format" : "%proc.exe %proc.args"
		},
		{
			"filter" : "user.name=$username and evt.type=chdir and proc.name=bash",
			"format" : "cd %evt.arg.path"
		}
	]
}