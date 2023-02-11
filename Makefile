CLANG_FORMAT_EXE ?= clang-format
CLANG_FORMAT_DESIRED_VERSION := "14.0.0"
CLANG_FORMAT_VERSION := "$(shell ${CLANG_FORMAT_EXE} --version 2> /dev/null | grep -o '[0-9]*\.[0-9]*\.[0-9]*')"

CMAKE_FORMAT_EXE ?= cmake-format
CMAKE_FORMAT_DESIRED_VERSION := "0.6.13"
CMAKE_FORMAT_VERSION := "$(shell ${CMAKE_FORMAT_EXE} --version 2> /dev/null | grep -o '[0-9]*\.[0-9]*\.[0-9]*')"

PROJECT_ROOT_DIR = $(shell git rev-parse --show-toplevel)

######################
#    Clang-format    #
######################

.PHONY: clang-format-require
clang-format-require:
ifeq (, $(CLANG_FORMAT_VERSION))
	@echo "${CLANG_FORMAT_EXE} is not installed. Please read the 'coding style' doc to get more info."
	@exit 1
endif

ifneq ($(CLANG_FORMAT_VERSION), $(CLANG_FORMAT_DESIRED_VERSION))
	@echo "${CLANG_FORMAT_EXE} version is not '${CLANG_FORMAT_DESIRED_VERSION}'. Actual version is '${CLANG_FORMAT_VERSION}'"
	@exit 1
endif
	@echo "Correct version of clang-format: '${CLANG_FORMAT_VERSION}'" 

.PHONY: format-clang
format-clang: clang-format-require
	git ls-files --directory ${PROJECT_ROOT_DIR} | grep -E '\.(cpp|h|c)$$' | xargs ${CLANG_FORMAT_EXE} -Werror --style=file:${PROJECT_ROOT_DIR}/.clang-format -i

.PHONY: check-clang
check-clang: clang-format-require
	git ls-files --directory ${PROJECT_ROOT_DIR} | grep -E '\.(cpp|h|c)$$' | xargs ${CLANG_FORMAT_EXE} -Werror --style=file:${PROJECT_ROOT_DIR}/.clang-format -n

######################
#    Cmake-format    #
######################

.PHONY: cmake-format-require
cmake-format-require:
ifeq (, $(CMAKE_FORMAT_VERSION))
	@echo "${CMAKE_FORMAT_EXE} is not installed. Please read the 'coding style' doc to get more info."
	@exit 1
endif

ifneq ("$(CMAKE_FORMAT_VERSION)", $(CMAKE_FORMAT_DESIRED_VERSION))
	@echo "${CMAKE_FORMAT_EXE} version is not '${CMAKE_FORMAT_DESIRED_VERSION}'. Actual version is '${CMAKE_FORMAT_VERSION}'"
	@exit 1
endif

.PHONY: format-cmake
format-cmake: cmake-format-require
	git ls-files --directory ${PROJECT_ROOT_DIR} | grep -E '\.(cmake)$$|CMakeLists.txt$$' | xargs ${CMAKE_FORMAT_EXE} --config-files ${PROJECT_ROOT_DIR}/.cmake-format.json -i

.PHONY: check-cmake
check-cmake: cmake-format-require
	git ls-files --directory ${PROJECT_ROOT_DIR} | grep -E '\.(cmake)$$|CMakeLists.txt$$' | xargs ${CMAKE_FORMAT_EXE} --config-files ${PROJECT_ROOT_DIR}/.cmake-format.json --check

# Add new formatters here...

######################
#        All         #
######################

.PHONY: format-all
format-all: format-clang format-cmake

.PHONY: check-all
check-all: check-clang check-cmake
