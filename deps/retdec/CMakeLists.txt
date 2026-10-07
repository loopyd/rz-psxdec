cmake_minimum_required(VERSION 3.8)

set(RETDEC_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../retdec-psx"
	CACHE PATH "Sibling RetDec source used by the bundled plugin")
if(NOT EXISTS "${RETDEC_SOURCE_DIR}/CMakeLists.txt")
	message(FATAL_ERROR "Missing sibling RetDec source: ${RETDEC_SOURCE_DIR}")
endif()

add_subdirectory(
	"${RETDEC_SOURCE_DIR}"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec"
)

install(
	DIRECTORY
		"${RETDEC_SOURCE_DIR}/support/ordinals"
		"${RETDEC_SOURCE_DIR}/support/yara_patterns"
		"${RETDEC_SOURCE_DIR}/support/types"
	DESTINATION
		"${RIZIN_INSTALL_PLUGDIR}/support/retdec/"
)
