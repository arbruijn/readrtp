add_executable(test_apply
    test_apply.cpp
)
target_link_libraries(test_apply PRIVATE readrtp)
add_test(NAME test_apply COMMAND test_apply)
set_tests_properties(test_apply PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

add_executable(test_parse
    test_parse.cpp
)
target_link_libraries(test_parse PRIVATE readrtp)
add_test(NAME test_parse COMMAND test_parse)
set_tests_properties(test_parse PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

add_executable(test_checksum
    test_checksum.cpp
)
target_link_libraries(test_checksum PRIVATE readrtp)
add_test(NAME test_checksum COMMAND test_checksum)
set_tests_properties(test_checksum PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

add_executable(test_decompression
    test_decompression.cpp
)
target_link_libraries(test_decompression PRIVATE readrtp)
add_test(NAME test_decompression COMMAND test_decompression)
set_tests_properties(test_decompression PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)
