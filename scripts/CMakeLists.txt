configure_file(debian/postinst.in "${CMAKE_CURRENT_SOURCE_DIR}/debian/postinst")
configure_file(debian/prerm.in "${CMAKE_CURRENT_SOURCE_DIR}/debian/prerm")

set(CLEAN_FILES
	"${CMAKE_CURRENT_SOURCE_DIR}/debian/postinst"
	"${CMAKE_CURRENT_SOURCE_DIR}/debian/prerm")

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${CLEAN_FILES}")

add_custom_target(scripts)
