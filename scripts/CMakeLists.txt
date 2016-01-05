configure_file(debian/postinst.in debian/postinst)
configure_file(debian/prerm.in debian/prerm)

install(FILES completions/bash/sysdig
	DESTINATION share/bash-completion/completions)

install(FILES completions/zsh/_sysdig
	DESTINATION share/zsh/vendor-completions)

install(FILES completions/zsh/_sysdig
	DESTINATION share/zsh/site-functions)

install(PROGRAMS sysdig-probe-loader
	DESTINATION bin)
