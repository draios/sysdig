find_program(PANDOC pandoc)

if (PANDOC)
	add_custom_target(man_sysdig ALL
		COMMAND ${PANDOC} -s -f markdown_github -t man sysdig.md -o ${CMAKE_CURRENT_BINARY_DIR}/sysdig.8
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
		VERBATIM)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/sysdig.8
		DESTINATION share/man/man8)

	add_custom_target(man_csysdig ALL
		COMMAND ${PANDOC} -s -f markdown_github -t man csysdig.md -o ${CMAKE_CURRENT_BINARY_DIR}/csysdig.8
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
		VERBATIM)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/csysdig.8
		DESTINATION share/man/man8)
else()
	install(FILES sysdig.8
		DESTINATION share/man/man8)

	install(FILES csysdig.8
		DESTINATION share/man/man8)
endif()
