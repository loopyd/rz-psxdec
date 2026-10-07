set(CUTTER_PLUGIN_INCLUDE ${PROJECT_SOURCE_DIR}/include/cutter-plugin)

set(SOURCE
	${CUTTER_PLUGIN_INCLUDE}/core_plugin.h
	core_plugin.cpp
)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

add_library(retdec_cutter MODULE ${SOURCE})
target_include_directories(retdec_cutter PUBLIC ${PROJECT_SOURCE_DIR}/include/)
target_link_libraries(retdec_cutter PUBLIC rz-psxdec Cutter::Cutter)

install(TARGETS retdec_cutter DESTINATION "${CUTTER_INSTALL_PLUGDIR}")
