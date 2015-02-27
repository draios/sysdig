configure_file(debian/postinst.in debian/postinst)
configure_file(debian/prerm.in debian/prerm)

install(FILES completions/bash/sysdig
	DESTINATION "${DIR_ETC}/bash_completion.d")

install(FILES completions/zsh/_sysdig
	DESTINATION share/zsh/vendor-completions)

install(FILES completions/zsh/_sysdig
	DESTINATION share/zsh/site-functions)

install(PROGRAMS sysdig-probe-loader
	DESTINATION bin)
