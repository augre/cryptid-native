CMAKE_MINIMUM_REQUIRED(VERSION 2.8)                      

PROJECT(cryptid_native)

SET(CMAKE_C_FLAGS "$ENV{CFLAGS} -std=c99 -Wall -Wextra -Werror -c") 

SET(INCLUDE_PATH ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/include/complex  ${PROJECT_SOURCE_DIR}/include/elliptic   ${PROJECT_SOURCE_DIR}/include/identity-based ${PROJECT_SOURCE_DIR}/include/util ${PROJECT_SOURCE_DIR}/dependencies/sha/include/) 
MESSAGE(STATUS "Include Path, ${INCLUDE_PATH}") 

#${PROJECT_SOURCE_DIR}/src/complex ${PROJECT_SOURCE_DIR}/src/elliptic ${PROJECT_SOURCE_DIR}/src/identity-based ${PROJECT_SOURCE_DIR}/src/util
SET(SOURCE_PATH1 ${PROJECT_SOURCE_DIR}/src ) 
SET(SOURCE_PATH2 ${PROJECT_SOURCE_DIR}/src/complex) 
SET(SOURCE_PATH3 ${PROJECT_SOURCE_DIR}/src/elliptic) 
SET(SOURCE_PATH4 ${PROJECT_SOURCE_DIR}/src/identity-based) 
SET(SOURCE_PATH5 ${PROJECT_SOURCE_DIR}/src/util) 
SET(SOURCE_PATH6 ${PROJECT_SOURCE_DIR}/dependencies/sha/src/) 
MESSAGE(STATUS "Source Path , ${SOURCE_PATH}") 

INCLUDE_DIRECTORIES(${INCLUDE_PATH}) 

AUX_SOURCE_DIRECTORY(${SOURCE_PATH1} SRC_LIST) 
AUX_SOURCE_DIRECTORY(${SOURCE_PATH2} SRC_LIST) 
AUX_SOURCE_DIRECTORY(${SOURCE_PATH3} SRC_LIST) 
AUX_SOURCE_DIRECTORY(${SOURCE_PATH4} SRC_LIST) 
AUX_SOURCE_DIRECTORY(${SOURCE_PATH5} SRC_LIST) 
AUX_SOURCE_DIRECTORY(${SOURCE_PATH6} SRC_LIST) 

SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib) 
MESSAGE(STATUS "Library Output Path, " ${PROJECT_BINARY_DIR/lib}) 


ADD_LIBRARY(cryptid STATIC ${SRC_LIST})

# SET_TARGET_PROPERTIES(b_staticlib PROPERTIES OUTPUT_NAME "mymath")

