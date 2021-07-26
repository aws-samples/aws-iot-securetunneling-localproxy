### Building local proxy in Windows
* Install visual studio 2017 ( Select Desktop development with c++ while installing ).
* Install Cmake 3.16+ from https://www.cmake.org/download.
* Install Strawberry Perl 5.30+ using link https://www.perl.org/get.html.
* Install git using link https://git-scm.com/download/win
* Install NASM using link https://www.nasm.us/
* Install the following dependencies (Choose visual studio command prompt based on architecture):
	* Download and install zlib:
		* Use Visual Studio native tool command prompt in admin mode.
		* `git clone -b v1.2.8 https://github.com/madler/zlib.git`
		* `cd zlib`
		* `mkdir build`
		* `cd build`
		* `cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release ../`
		* `nmake`
		* `nmake install` (installs zlib inside C:\Program Files (x86)\ )
		* Update PATH environment variable to add the dll for zlib which is inside C:\Program Files (x86)\zlib\bin
	* Download and install openssl
		* Use Visual Studio native tool command prompt in admin mode.
		* `git clone https://github.com/openssl/openssl.git`
		* `cd openssl`
		* `git checkout OpenSSL_1_1_1-stable`
		* `perl Configure { VC-WIN32 | VC-WIN64A | VC-WIN64I | VC-CE }` (Choose one of the options based on your architecture )
		* `nmake`
		* `nmake install` (installs OpenSSL inside C:\Program Files\)
		* Update PATH environment variable to add the dll for openssl which is inside C:\Program Files\OpenSSL\bin
		* Download and install catch2
		* Use Visual Studio native tool command prompt in admin mode.
		* `git clone --branch v2.13.6 https://github.com/catchorg/Catch2.git`
		* `cd Catch2`
		* `mkdir build`
		* `cd build`
		* `cmake -DBUILD_TESTING=OFF -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release ../` ( Install python if you want to execute test )
		* `nmake`
		* `nmake install` ( install catch2 inside C:\Program Files (x86)\ )
	* Download and install protobuf
		* Download from https://github.com/protocolbuffers/protobuf/releases/download/v3.17.3/protobuf-all-3.17.3.tar.gz
		* Extract protobuf-all-3.17.3.tar.gz
		* Use Visual Studio native tool command prompt
		* `cd path/to/protobuf-3.17.3`
		* `cd cmake`
		* `mkdir build`
		* `cd build`
		* `cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release -Dprotobuf_MSVC_STATIC_RUNTIME=OFF ../`
		* `nmake`
		* `nmake install` ( install protobuf inside C:\Program Files (x86)\ )
	* Download and install boost
		* Download from https://boostorg.jfrog.io/artifactory/main/release/1.76.0/source/boost_1_76_0.tar.gz
		* Extract boost_1_76_0.tar.gz
		* Use Visual Studio native tool command prompt
		* `cd path/to/boost_1_76_0`
		* `bootstrap.bat`
		* `.\b2 toolset=msvc address-model={32 | 64} install define=BOOST_WINAPI_VERSION_WIN10` ( installs boost inside C:\)
			* Replace `BOOST_WINAPI_VERSION_WIN10` with the appropriate macro from [here](https://www.boost.org/doc/libs/develop/libs/winapi/doc/html/winapi/config.html)
	* Download and build aws-iot-securetunneling-localproxy
		* Use Visual Studio native tool comand prompt in admin mode
		* `git clone https://github.com/aws-samples/aws-iot-securetunneling-localproxy.git`
		* `cd aws-iot-securetunneling-localproxy`
		* `mkdir build`
		* `cd build`
		* Build the cmake project. Replace <_WIN32_WINNT> with the appropriate value based on [your OS from here](https://docs.microsoft.com/en-us/cpp/porting/modifying-winver-and-win32-winnt?view=vs-2019)
			* For visual studio 2019
			```
			cmake -DWIN32_WINNT=<_WIN32_WINNT> -DBoost_USE_STATIC_LIBS=ON -DCMAKE_PREFIX_PATH="C:\Boost;C:\Program Files (x86)\Catch2;C:\Program Files (x86)\protobuf;C:\Program Files\OpenSSL" -G "Visual Studio 16 2019" -A x64 ..\
			```
			* for visual studio 2017
			```
			cmake -DWIN32_WINNT=<_WIN32_WINNT> -DBoost_USE_STATIC_LIBS=ON -DCMAKE_PREFIX_PATH="C:\Boost;C:\Program Files (x86)\Catch2;C:\Program Files (x86)\protobuf;C:\Program Files\OpenSSL" -G "Visual Studio 15 2017 <Win64/Win32>" ..\
			```
		* `msbuild localproxy.vcxproj -p:Configuration=Release` ( builds localproxy.exe inside bin\Release folder )
	* Follow [instructions](https://github.com/aws-samples/aws-iot-securetunneling-localproxy) under heading `Security Considerations` to run local proxy on a window OS.
