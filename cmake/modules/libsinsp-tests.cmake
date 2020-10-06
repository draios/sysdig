include(gtest)

# Add unit test directories
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../../userspace/libsinsp/test ${CMAKE_BINARY_DIR}/libsinsp/test)

# Add command to run all unit tests at once via the make system.
# This is preferred vs using ctest's add_test because it will build
# the code and output to stdout.
add_custom_target(run-unit-tests
	COMMAND ${CMAKE_MAKE_PROGRAM} run-unit-test-libsinsp
	)
