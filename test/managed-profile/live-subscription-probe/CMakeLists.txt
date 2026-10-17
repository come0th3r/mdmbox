cmake_minimum_required(VERSION 3.16)
project(mdmbox_live_subscription_probe LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Core Network)
find_package(yaml-cpp CONFIG REQUIRED)

add_executable(mdmbox_live_subscription_probe
    main.cpp
    ../../../sub/InstallationIdentity.cpp
    ../../../sub/ManagedProfile.cpp
    ../../../sub/ManagedProfileStore.cpp
    ../../../sub/MihomoValidator.cpp
    ../../../sub/SubscriptionContract.cpp
    ../../../sub/SubscriptionDownloader.cpp
    ../../../sub/SubscriptionService.cpp
)
target_link_libraries(mdmbox_live_subscription_probe PRIVATE Qt6::Core Qt6::Network yaml-cpp)
