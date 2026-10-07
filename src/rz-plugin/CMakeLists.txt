find_package(Git REQUIRED)
set(RZ_PSXDEC_REVISION "" CACHE STRING "Expected rz-psxdec Git revision")
set(RETDEC_PSX_REVISION "" CACHE STRING "Expected retdec-psx Git revision")
foreach(FORK RZ_PSXDEC RETDEC_PSX)
	if(FORK STREQUAL "RZ_PSXDEC")
		set(FORK_SOURCE_DIR "${PROJECT_SOURCE_DIR}")
	else()
		set(FORK_SOURCE_DIR "${RETDEC_SOURCE_DIR}")
	endif()
	execute_process(
		COMMAND "${GIT_EXECUTABLE}" -C "${FORK_SOURCE_DIR}" rev-parse --verify HEAD
		RESULT_VARIABLE GIT_RESULT
		OUTPUT_VARIABLE ${FORK}_GIT_COMMIT
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)
	string(LENGTH "${${FORK}_GIT_COMMIT}" COMMIT_LENGTH)
	if(NOT GIT_RESULT EQUAL 0 OR NOT COMMIT_LENGTH EQUAL 40
			OR NOT "${${FORK}_GIT_COMMIT}" MATCHES "^[0-9a-f]+$")
		message(FATAL_ERROR "Cannot identify ${FORK} Git HEAD in ${FORK_SOURCE_DIR}")
	endif()
	if(NOT "${${FORK}_REVISION}" STREQUAL ""
			AND NOT "${${FORK}_REVISION}" STREQUAL "${${FORK}_GIT_COMMIT}")
		message(FATAL_ERROR "${FORK}_REVISION differs from actual Git HEAD")
	endif()
endforeach()
configure_file(
	"${PROJECT_SOURCE_DIR}/include/rz-plugin/version.h.in"
	"${CMAKE_CURRENT_BINARY_DIR}/generated/rz-plugin/version.h"
	@ONLY
)

set(SOURCES
	rzretdec.cpp
	data.cpp
	utils.cpp
	cgen.cpp
	console/console.cpp
	console/data_analysis.cpp
	console/original_range.cpp
	console/decompiler.cpp
	registration.cpp
)

add_library(rz-psxdec SHARED ${SOURCES})
target_link_libraries(rz-psxdec PUBLIC retdec::config) # include dirs from here are used by the cutter plugin

set(CORE_LIBS)
if (UNIX AND NOT APPLE)
	list(APPEND CORE_LIBS -Wl,-Bsymbolic)
endif()
list(APPEND CORE_LIBS retdec::retdec)
if (MSVC)
	list(APPEND CORE_LIBS
		retdec::bin2llvmir -WHOLEARCHIVE:$<TARGET_FILE_NAME:retdec::bin2llvmir>
		retdec::llvmir2hll -WHOLEARCHIVE:$<TARGET_FILE_NAME:retdec::llvmir2hll>
		retdec::llvmir2hll -WHOLEARCHIVE:$<TARGET_FILE_NAME:retdec::deps::capstone>
	)

	set_property(TARGET rz-psxdec
		APPEND_STRING PROPERTY LINK_FLAGS " /FORCE:MULTIPLE"
	)
	# Increase the stack size of the created binaries on MS Windows because the
	# default value is too small. The default Linux value is 8388608 (8 MB).
	set_property(TARGET rz-psxdec
		APPEND_STRING PROPERTY LINK_FLAGS " /STACK:16777216"
	)
	# Allow the 32b version of bin2llvmir on Windows handle addresses larger
	# than 2 GB (up to 4 GB).
	if(CMAKE_SIZEOF_VOID_P MATCHES "4")
		set_property(TARGET rz-psxdec
			APPEND_STRING PROPERTY LINK_FLAGS " /LARGEADDRESSAWARE"
		)
	endif()
elseif (APPLE)
	list(APPEND CORE_LIBS
		-Wl,-force_load retdec::bin2llvmir
		-Wl,-force_load retdec::llvmir2hll
		-Wl,-force_load retdec::deps::capstone
	)
else ()
	list(APPEND CORE_LIBS
		-Wl,--whole-archive retdec::bin2llvmir -Wl,--no-whole-archive
		-Wl,--whole-archive retdec::llvmir2hll -Wl,--no-whole-archive
		-Wl,--whole-archive retdec::deps::capstone -Wl,--no-whole-archive
	)
endif()
find_library(STD_CPP_FS stdc++fs)
if (STD_CPP_FS)
	message("-- Linking with ${STD_CPP_FS} library")
	list(APPEND CORE_LIBS
		stdc++fs
	)
else()
	message("-- Library stdc++fs NOT FOUND -> linking rz-psxdec without stdc++fs library")
endif()
# Rizin::Core must be last to ensure symbols like cs_disasm_* are loaded from retdec's
# capstone instead of librz_asm on macOS.
target_link_libraries(rz-psxdec PRIVATE ${CORE_LIBS} Rizin::Core)

target_include_directories(rz-psxdec PUBLIC
	${PROJECT_SOURCE_DIR}/include/
	${CMAKE_CURRENT_BINARY_DIR}/generated/
)

set_target_properties(rz-psxdec PROPERTIES
	OUTPUT_NAME rz-psxdec
	PREFIX ""
)

install(TARGETS rz-psxdec DESTINATION "${RIZIN_INSTALL_PLUGDIR}")
