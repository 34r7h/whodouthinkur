# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 4.0

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/homebrew/bin/cmake

# The command to remove a file.
RM = /opt/homebrew/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main

# Include any dependencies generated for this target.
include apps/CMakeFiles/example_nistapi_mayo_3.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include apps/CMakeFiles/example_nistapi_mayo_3.dir/compiler_depend.make

# Include the progress variables for this target.
include apps/CMakeFiles/example_nistapi_mayo_3.dir/progress.make

# Include the compile flags for this target's objects.
include apps/CMakeFiles/example_nistapi_mayo_3.dir/flags.make

apps/CMakeFiles/example_nistapi_mayo_3.dir/codegen:
.PHONY : apps/CMakeFiles/example_nistapi_mayo_3.dir/codegen

apps/CMakeFiles/example_nistapi_mayo_3.dir/example_nistapi.c.o: apps/CMakeFiles/example_nistapi_mayo_3.dir/flags.make
apps/CMakeFiles/example_nistapi_mayo_3.dir/example_nistapi.c.o: apps/example_nistapi.c
apps/CMakeFiles/example_nistapi_mayo_3.dir/example_nistapi.c.o: apps/CMakeFiles/example_nistapi_mayo_3.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object apps/CMakeFiles/example_nistapi_mayo_3.dir/example_nistapi.c.o"
	cd /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main/apps && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT apps/CMakeFiles/example_nistapi_mayo_3.dir/example_nistapi.c.o -MF CMakeFiles/example_nistapi_mayo_3.dir/example_nistapi.c.o.d -o CMakeFiles/example_nistapi_mayo_3.dir/example_nistapi.c.o -c /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main/apps/example_nistapi.c

apps/CMakeFiles/example_nistapi_mayo_3.dir/example_nistapi.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/example_nistapi_mayo_3.dir/example_nistapi.c.i"
	cd /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main/apps && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main/apps/example_nistapi.c > CMakeFiles/example_nistapi_mayo_3.dir/example_nistapi.c.i

apps/CMakeFiles/example_nistapi_mayo_3.dir/example_nistapi.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/example_nistapi_mayo_3.dir/example_nistapi.c.s"
	cd /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main/apps && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main/apps/example_nistapi.c -o CMakeFiles/example_nistapi_mayo_3.dir/example_nistapi.c.s

# Object files for target example_nistapi_mayo_3
example_nistapi_mayo_3_OBJECTS = \
"CMakeFiles/example_nistapi_mayo_3.dir/example_nistapi.c.o"

# External object files for target example_nistapi_mayo_3
example_nistapi_mayo_3_EXTERNAL_OBJECTS =

apps/example_nistapi_mayo_3: apps/CMakeFiles/example_nistapi_mayo_3.dir/example_nistapi.c.o
apps/example_nistapi_mayo_3: apps/CMakeFiles/example_nistapi_mayo_3.dir/build.make
apps/example_nistapi_mayo_3: src/libmayo_3_nistapi.a
apps/example_nistapi_mayo_3: src/libmayo_3.a
apps/example_nistapi_mayo_3: src/libmayo_common_sys.a
apps/example_nistapi_mayo_3: apps/CMakeFiles/example_nistapi_mayo_3.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable example_nistapi_mayo_3"
	cd /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main/apps && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/example_nistapi_mayo_3.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
apps/CMakeFiles/example_nistapi_mayo_3.dir/build: apps/example_nistapi_mayo_3
.PHONY : apps/CMakeFiles/example_nistapi_mayo_3.dir/build

apps/CMakeFiles/example_nistapi_mayo_3.dir/clean:
	cd /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main/apps && $(CMAKE_COMMAND) -P CMakeFiles/example_nistapi_mayo_3.dir/cmake_clean.cmake
.PHONY : apps/CMakeFiles/example_nistapi_mayo_3.dir/clean

apps/CMakeFiles/example_nistapi_mayo_3.dir/depend:
	cd /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main/apps /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main/apps /Users/34r7h/Documents/dev/fun/cubix/identity/MAYO-C-main/apps/CMakeFiles/example_nistapi_mayo_3.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : apps/CMakeFiles/example_nistapi_mayo_3.dir/depend

