### Building local proxy in Windows
* Install visual studio 2017 ( Select Desktop development with c++ while installing ).
* Install Cmake 3.16+ from https://www.cmake.org/download.
* Install Strawberry Perl 5.30+ using link https://www.perl.org/get.html.
* Install git using link https://git-scm.com/download/win
* Install NASM using link https://www.nasm.us/
* Install the following dependencies (Choose visual studio command prompt based on architecture):
	* Download and install zlib:
		* Use Visual Studio native tool command prompt in admin mode.
		* git clone -b v1.2.8 https://github.com/madler/zlib.git
		* cd zlib
		* mkdir build & cd build
		* cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release ../
		* nmake & nmake install (installs zlib inside C:\Program Files (x86)\ )
		* Update PATH environment variable to add the dll for zlib which is inside C:\Program Files (x86)\zlib\bin
	* Download and install openssl
		* Use Visual Studio native tool command prompt in admin mode.
		* git clone https://github.com/openssl/openssl.git
		* cd openssl
		* git checkout OpenSSL_1_1_1-stable
		* perl Configure { VC-WIN32 | VC-WIN64A | VC-WIN64I | VC-CE } (Choose one of the options based on your architecture )
		* nmake & nmake install (installs OpenSSL inside C:\Program Files\)
		* Update PATH environment variable to add the dll for openssl which is inside C:\Program Files\OpenSSL\bin
		* Download and install catch2
		* Use Visual Studio native tool command prompt in admin mode.
		* git clone https://github.com/catchorg/Catch2.git
		* cd Catch2
		* mkdir build & cd build
		* cmake -DBUILD_TESTING=OFF -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release ../ ( Install python if you want to execute test )
		* nmake & nmake ( install catch2 inside C:\Program Files (x86)\ )
	* Download and install protobuf
		* Download from https://github.com/protocolbuffers/protobuf/releases/download/v3.6.1/protobuf-all-3.6.1.tar.gz
		* Extract protobuf-all-3.6.1.tar.gz
		* Use Visual Studio native tool command prompt
		* cd path/to/protobuf-3.6.1
		* cd cmake
		* mkdir build & cd build
		* cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release -Dprotobuf_MSVC_STATIC_RUNTIME=OFF ../
		* nmake & nmake install ( install protobuf inside C:\Program Files (x86)\ )
	* Download and install boost
		* Download from https://dl.bintray.com/boostorg/release/1.69.0/source/boost_1_69_0.tar.gz
		* Extract boost_1_69_0.tar.gz
		* Use Visual Studio native tool command prompt
		* cd path/to/boost_1_69_0
		* bootstrap.bat
		* .\b2 install ( installs boost inside C:\)
	* Download and build aws-iot-securetunneling-localproxy
		* Use Visual Studio native tool comand prompt in admin mode
		* git clone https://github.com/aws-samples/aws-iot-securetunneling-localproxy.git
		* cd aws-iot-securetunneling-localproxy
		* Edit CmakeList.txt file to make the following changes:
			* Replace set_property(GLOBAL PROPERTY Boost_USE_STATIC_LIBS ON) by set(Boost_USE_STATIC_LIBS ON)
			* Comment out line target_link_libraries(\${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} atomic) and target_link_libraries(\${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} atomic) by inserting # infront of those lines.
			* Replace the following  code block ( Replace WINAPI_VERSION using link https://docs.microsoft.com/en-us/cpp/porting/modifying-winver-and-win32-winnt?view=vs-2019 ).
			    ```
				    elseif (WIN32)
				     set(CUSTOM_COMPILER_FLAGS "/W4 /DYNAMICBASE /NXCOMPAT /analyze")
				     set(TEST_COMPILER_FLAGS "${CUSTOM_COMPILER_FLAGS} /D_AWSIOT_TUNNELING_NO_SSL")
				    endif ()
                ```
		     With the following code block:
             ```	
              elseif (WIN32)
                  set(CUSTOM_COMPILER_FLAGS "/W4 /DYNAMICBASE /NXCOMPAT /analyze")
                  set(TEST_COMPILER_FLAGS "${CUSTOM_COMPILER_FLAGS} /D_AWSIOT_TUNNELING_NO_SSL")
                  add_definitions(-D_WIN32_WINNT=<WINAPI_VERSION>)
                  add_definitions(-D_BOOST_USE_WINAPI_VERSION=<WINAPI_VERSION>)
              endif ()
			```
		* mkdir build & cd build
		* cmake -DCMAKE_PREFIX_PATH="C:\Boost;C:\Program Files (x86)\Catch2;C:\Program Files (x86)\protobuf;C:\Program Files\OpenSSL" -G "Visual Studio 15 2017 <Win64/Win32>" ..\
		* msbuild localproxy.vcxproj -p:Configuration=Release ( builds localproxy.exe inside bin\Release folder )
	* Follow [instructions](https://github.com/aws-samples/aws-iot-securetunneling-localproxy) under heading `Security Considerations` to run local proxy on a window OS.
