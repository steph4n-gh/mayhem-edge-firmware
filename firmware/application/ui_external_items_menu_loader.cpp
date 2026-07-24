#include "ui_external_items_menu_loader.hpp"

#if HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC
#include <cstring>
#include "precision_rx_segmented_geometry.hpp"
#endif

#include "sd_card.hpp"
#include "file_path.hpp"
#include "memory_map.hpp"
#include "portapack_shared_memory.hpp"
#include "ui_standalone_view.hpp"

#include "i2cdevmanager.hpp"
#include "i2cdev_ppmod.hpp"

namespace ui {

/* static */ std::vector<DynamicBitmap<16, 16>> ExternalItemsMenuLoader::bitmaps;

constexpr size_t external_app_read_chunk_size = 4 * 1024;
static_assert(external_app_read_chunk_size <= 16 * 1024);

#if HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC
constexpr uint32_t precision_rx_shared_memory_base =
    portapack::memory::map::shared_memory.base();
constexpr size_t precision_rx_bb_data_offset =
    offsetof(SharedMemory, bb_data);
constexpr size_t precision_rx_bb_data_size =
    sizeof(decltype(SharedMemory::bb_data));
constexpr size_t precision_rx_aux0_max_size =
    precision_rx_bb_data_size -
    SharedMemory::m4_panic_context_reserved_bytes;
constexpr uint32_t precision_rx_aux0_load_address =
    precision_rx_shared_memory_base +
    precision_rx_bb_data_offset +
    SharedMemory::m4_panic_context_reserved_bytes;
constexpr uint32_t precision_rx_aux0_end_address =
    precision_rx_aux0_load_address + precision_rx_aux0_max_size;
constexpr uint32_t precision_rx_aux1_load_address =
    precision_rx_shared_memory_base + sizeof(SharedMemory);
constexpr size_t precision_rx_aux1_max_size =
    portapack::memory::map::shared_memory.size() - sizeof(SharedMemory);
constexpr uint32_t precision_rx_aux1_end_address =
    precision_rx_aux1_load_address + precision_rx_aux1_max_size;
constexpr size_t precision_rx_live_field_gap_size =
    precision_rx_aux1_load_address - precision_rx_aux0_end_address;
static_assert(precision_rx_segmented_geometry_version == 1);
static_assert(precision_rx_shared_memory_base == 0x10088000);
static_assert(portapack::memory::map::shared_memory.size() == 8192);
static_assert(precision_rx_segmented_m4_load_address ==
              portapack::memory::map::m4_code.base());
static_assert(precision_rx_segmented_m0_load_address ==
              precision_rx_segmented_m4_load_address +
                  precision_rx_segmented_m4_size);
static_assert(precision_rx_segmented_code_window_size ==
              portapack::memory::map::m4_code.size());
static_assert(precision_rx_bb_data_offset == 4200);
static_assert(precision_rx_bb_data_size == 2496);
static_assert(SharedMemory::m4_panic_context_reserved_bytes == 112);
static_assert(sizeof(SharedMemory) == 6752);
static_assert(precision_rx_aux0_load_address == 0x100890D8);
static_assert(precision_rx_aux0_max_size == 2384);
static_assert(precision_rx_aux0_end_address == 0x10089A28);
static_assert(precision_rx_segmented_aux0_load_address ==
              precision_rx_aux0_load_address);
static_assert(precision_rx_segmented_aux0_max_size ==
              precision_rx_aux0_max_size);
static_assert(precision_rx_aux1_load_address == 0x10089A60);
static_assert(precision_rx_live_field_gap_size == 56);
static_assert(precision_rx_aux1_max_size == 1440);
static_assert(precision_rx_aux1_end_address == 0x1008A000);
static_assert(precision_rx_segmented_aux1_load_address ==
              precision_rx_aux1_load_address);
static_assert(precision_rx_segmented_aux1_max_size ==
              precision_rx_aux1_max_size);
static_assert(precision_rx_segmented_shared_memory_end ==
              precision_rx_aux1_end_address);
static_assert(precision_rx_segmented_checksum_size ==
              EXTERNAL_APP_CHECKSUM_SIZE);
static_assert(precision_rx_segmented_file_size == 36576);
static_assert((precision_rx_segmented_main_size |
               precision_rx_segmented_m4_size |
               precision_rx_segmented_aux0_size |
               precision_rx_segmented_aux1_size) %
                  4U ==
              0);
static_assert(precision_rx_segmented_main_size >= sizeof(application_information_t));
static_assert(precision_rx_segmented_main_size +
                      precision_rx_segmented_m4_size <=
                  precision_rx_segmented_code_window_size);
static_assert(precision_rx_segmented_aux0_size <=
              precision_rx_segmented_aux0_max_size);
static_assert(precision_rx_segmented_aux1_size <=
              precision_rx_segmented_aux1_max_size);
static_assert(precision_rx_segmented_image_size == 36532);
static_assert(sizeof(portapack::spi_flash::image_tag_t) ==
              sizeof(precision_rx_m4_tag_word));
#endif

__attribute__((noinline)) static bool read_exact(File& file, void* data, size_t size) {
    auto* destination = static_cast<uint8_t*>(data);
    while (size != 0) {
        const auto chunk_size = size > external_app_read_chunk_size
                                    ? external_app_read_chunk_size
                                    : size;
        const auto result = file.read(destination, chunk_size);
        if (!result || result.value() != chunk_size)
            return false;
        destination += chunk_size;
        size -= chunk_size;
    }
    return true;
}

/*
 * Keep file validation and image loading in a separate, non-inlined frame.
 * External app entry points construct complete views and may load settings;
 * invoking one while this function's File and checksum buffer are still live
 * can exceed the small stacks used by non-UI callers.
 */
__attribute__((noinline)) static bool prepare_external_app(
    const std::filesystem::path& file_path,
    externalAppEntry_t& entry) {
    File app;

    auto open_error = app.open(file_path);
    if (open_error)
        return false;

    application_information_t application_information = {};

    if (!read_exact(app, &application_information, sizeof(application_information_t)))
        return false;

    // Compatibility must be enforced at the execution boundary. Menu discovery
    // is not authoritative because callers such as USB `appstart` invoke this
    // function directly by path.
    if (!external_app_is_compatible(application_information))
        return false;

    const auto file_size = app.size();
#if HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC
    uint32_t m4_tag_word;
    memcpy(
        &m4_tag_word,
        &application_information.m4_app_tag,
        sizeof(m4_tag_word));
    const bool is_segmented_precision_rx =
        m4_tag_word == precision_rx_m4_tag_word;
#else
    constexpr auto maximum_file_size = EXTERNAL_APP_MAX_FILE_SIZE;
#endif
    if (file_size < sizeof(application_information_t) + EXTERNAL_APP_CHECKSUM_SIZE ||
#if HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC
        (is_segmented_precision_rx &&
         file_size != precision_rx_segmented_file_size) ||
        (!is_segmented_precision_rx &&
         file_size > EXTERNAL_APP_MAX_FILE_SIZE) ||
#else
        file_size > maximum_file_size ||
#endif
        (file_size & 3U) != 0)
        return false;

    // Validate the complete file through a fixed, safe buffer before using any
    // file-provided pointer, offset, or entry point.
    if (!app.seek(0))
        return false;
    alignas(uint32_t) uint8_t checksum_buffer[std::filesystem::max_file_block_size];
    uint32_t checksum = 0;
    auto remaining = static_cast<size_t>(file_size);
    while (remaining != 0) {
        const auto bytes_to_read = std::min(sizeof(checksum_buffer), remaining);
        if (!read_exact(app, checksum_buffer, bytes_to_read))
            return false;
        checksum += simple_checksum(
            reinterpret_cast<uint32_t>(checksum_buffer), bytes_to_read);
        remaining -= bytes_to_read;
    }
    if (checksum != EXT_APP_EXPECTED_CHECKSUM)
        return false;

    const auto payload_size = static_cast<size_t>(file_size) - EXTERNAL_APP_CHECKSUM_SIZE;
    const auto m4_offset = static_cast<size_t>(application_information.m4_app_offset);

#if HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC
    size_t m0_image_size;
    size_t m4_image_size;
    if (is_segmented_precision_rx) {
        if (m4_offset != precision_rx_segmented_main_size)
            return false;
        m0_image_size = precision_rx_segmented_main_size;
        m4_image_size = precision_rx_segmented_m4_size;
    } else {
        if (m4_offset != 0 &&
            ((m4_offset & 3U) != 0 ||
             m4_offset < sizeof(application_information_t) ||
             m4_offset >= payload_size))
            return false;
        m0_image_size = m4_offset == 0 ? payload_size : m4_offset;
        m4_image_size = payload_size - m0_image_size;
    }

    const auto expected_m0_base =
        precision_rx_segmented_m4_load_address + m4_image_size;
    const auto supplied_m0_base = reinterpret_cast<uint32_t>(application_information.memory_location);
    const auto supplied_entry =
        reinterpret_cast<uint32_t>(application_information.externalAppEntry);
    const auto entry_address = supplied_entry & ~1U;
    if (supplied_m0_base != expected_m0_base ||
        (is_segmented_precision_rx && (supplied_entry & 1U) == 0) ||
        entry_address < expected_m0_base ||
        entry_address >= expected_m0_base + m0_image_size)
        return false;

    if (!app.seek(0) ||
        !read_exact(
            app, application_information.memory_location, m0_image_size) ||
        !read_exact(
            app,
            reinterpret_cast<void*>(precision_rx_segmented_m4_load_address),
            m4_image_size)
        || (is_segmented_precision_rx &&
            (!read_exact(
                 app,
                 reinterpret_cast<void*>(precision_rx_segmented_aux0_load_address),
                 precision_rx_segmented_aux0_size) ||
             !read_exact(
                 app,
                 reinterpret_cast<void*>(precision_rx_segmented_aux1_load_address),
                 precision_rx_segmented_aux1_size)))
    )
        return false;
#else
    if (m4_offset != 0 &&
        ((m4_offset & 3U) != 0 ||
         m4_offset < sizeof(application_information_t) ||
         m4_offset >= payload_size))
        return false;

    const auto m0_image_size = m4_offset == 0 ? payload_size : m4_offset;
    const auto m4_image_size = payload_size - m0_image_size;
    const auto expected_m0_base = portapack::memory::map::m4_code.base() + m4_image_size;
    const auto supplied_m0_base = reinterpret_cast<uint32_t>(application_information.memory_location);
    const auto entry_address = reinterpret_cast<uint32_t>(application_information.externalAppEntry) & ~1U;
    if (supplied_m0_base != expected_m0_base ||
        entry_address < expected_m0_base ||
        entry_address >= expected_m0_base + m0_image_size)
        return false;

    // The ranges are contiguous in the file, so one seek and two bounded,
    // exact-total copies avoid duplicate loop machinery after integrity succeeds.
    if (!app.seek(0))
        return false;
    if (!read_exact(app, application_information.memory_location, m0_image_size))
        return false;
    if (m4_image_size != 0) {
        if (!read_exact(
                app,
                reinterpret_cast<void*>(portapack::memory::map::m4_code.base()),
                m4_image_size))
            return false;
    }
#endif

    entry = application_information.externalAppEntry;
    return true;
}

// iterates over all possible ext apps-s, and if it is runnable on the current system, it'll call the callback, and pass minimal info. used to print to console, and for autostart setting's app list. where the minimal info is enough
// please keep in sync with load_external_items
/* static */ void ExternalItemsMenuLoader::load_all_external_items_callback(std::function<void(AppInfoConsole&)> callback, bool module_included) {
    if (!callback) return;

    auto dev = (i2cdev::I2cDev_PPmod*)i2cdev::I2CDevManager::get_dev_by_model(I2C_DEVMDL::I2CDECMDL_PPMOD);

    if (dev && module_included) {
        auto device_info = dev->readDeviceInfo();

        if (device_info.has_value()) {
            for (uint32_t i = 0; i < device_info->application_count; i++) {
                auto appInfo = dev->getStandaloneAppInfo(i);
                if (appInfo.has_value() == false) {
                    continue;
                }

                if (appInfo->header_version > CURRENT_STANDALONE_APPLICATION_API_VERSION)
                    continue;

                AppInfoConsole appInfoConsole = {reinterpret_cast<char*>(&appInfo->app_name[0]), reinterpret_cast<char*>(&appInfo->app_name[0]), appInfo->menu_location};
                callback(appInfoConsole);
            }
        }
    }

    if (sd_card::status() != sd_card::Status::Mounted)
        return;

    for (const auto& entry : std::filesystem::directory_iterator(apps_dir, u"*.ppma")) {
        auto filePath = apps_dir / entry.path();
        File app;

        auto openError = app.open(filePath);
        if (openError)
            continue;

        application_information_t application_information = {};

        if (!read_exact(app, &application_information, sizeof(application_information_t)))
            continue;

        if (!external_app_is_compatible(application_information))
            continue;

        std::string appshortname = filePath.filename().string();
        if (appshortname.size() >= 5 && appshortname.substr(appshortname.size() - 5) == ".ppma") {
            // Remove the ".ppma" suffix
            appshortname = appshortname.substr(0, appshortname.size() - 5);
        }
        AppInfoConsole appInfoConsole = {appshortname.c_str(), reinterpret_cast<char*>(&application_information.app_name[0]), application_information.menu_location};
        callback(appInfoConsole);
    }

    for (const auto& entry : std::filesystem::directory_iterator(apps_dir, u"*.ppmp")) {
        auto filePath = apps_dir / entry.path();
        File app;

        auto openError = app.open(filePath);
        if (openError)
            continue;

        standalone_application_information_t application_information = {};

        if (!read_exact(app, &application_information, sizeof(standalone_application_information_t)))
            continue;

        if (application_information.header_version > CURRENT_STANDALONE_APPLICATION_API_VERSION)
            continue;

        std::string appshortname = filePath.filename().string();
        if (appshortname.size() >= 5 && appshortname.substr(appshortname.size() - 5) == ".ppmp") {
            // Remove the ".ppmp" suffix
            appshortname = appshortname.substr(0, appshortname.size() - 5);
        }
        AppInfoConsole appInfoConsole = {appshortname.c_str(), reinterpret_cast<char*>(&application_information.app_name[0]), application_information.menu_location};
        callback(appInfoConsole);
    }
}

/* static */ std::vector<ExternalItemsMenuLoader::GridItemEx> ExternalItemsMenuLoader::load_external_items(app_location_t app_location, NavigationView& nav) {
    bitmaps.clear();

    std::vector<GridItemEx> external_apps;

    auto dev = (i2cdev::I2cDev_PPmod*)i2cdev::I2CDevManager::get_dev_by_model(I2C_DEVMDL::I2CDECMDL_PPMOD);

    if (dev) {
        auto device_info = dev->readDeviceInfo();

        if (device_info.has_value()) {
            for (uint32_t i = 0; i < device_info->application_count; i++) {
                auto appInfo = dev->getStandaloneAppInfo(i);
                if (appInfo.has_value() == false) {
                    continue;
                }

                if (appInfo->menu_location != app_location) {
                    continue;
                }

                if (appInfo->header_version > CURRENT_STANDALONE_APPLICATION_API_VERSION)
                    continue;

                GridItemEx gridItem = {};
                gridItem.text = reinterpret_cast<char*>(&appInfo->app_name[0]);

                gridItem.color = Color((uint16_t)appInfo->icon_color);

                auto dyn_bmp = DynamicBitmap<16, 16>{appInfo->bitmap_data};
                gridItem.bitmap = dyn_bmp.bitmap();
                bitmaps.push_back(std::move(dyn_bmp));

                gridItem.on_select = [&nav, appInfo, i]() {
                    auto dev2 = (i2cdev::I2cDev_PPmod*)i2cdev::I2CDevManager::get_dev_by_model(I2C_DEVMDL::I2CDECMDL_PPMOD);
                    if (dev2) {
                        dev2->lockDevice();
                        // auto app_image = reinterpret_cast<uint8_t*>(portapack::memory::map::m4_code.end() - appInfo->binary_size);
                        auto app_image = reinterpret_cast<uint8_t*>(portapack::memory::map::local_sram_0.base());
                        uint8_t errorcnt = 0;
                        for (size_t j = 0; j < appInfo->binary_size; j += 128) {
                            errorcnt = 0;
                            do {
                                auto segment = dev2->downloadStandaloneApp(i, j);
                                if (segment.size() != 128) {
                                    errorcnt++;
                                    if (errorcnt > 5) {
                                        break;
                                    }
                                } else {
                                    std::copy(segment.begin(), segment.end(), app_image + j);
                                    break;
                                }
                            } while (1);  // when ok, break. when errorcnt > 5, break
                            if (errorcnt > 5) {
                                nav.display_modal("Error", "Unable to download app.");
                                dev2->unlockDevice();
                                return;
                            }
                        }

                        if (!run_module_app(nav, app_image, appInfo->binary_size)) {
                            nav.display_modal("Error", "Unable to run downloaded app.");
                        }
                        dev2->unlockDevice();
                    } else
                        nav.display_modal("Error", "Unable to download app.");
                };

                gridItem.desired_position = -1;  // TODO: Where should we put the module's app icon? First? Last? Also configurable?

                external_apps.push_back(gridItem);
            }
        }
    }

    if (sd_card::status() != sd_card::Status::Mounted)
        return external_apps;

    for (const auto& entry : std::filesystem::directory_iterator(apps_dir, u"*.ppma")) {
        auto filePath = apps_dir / entry.path();
        File app;

        auto openError = app.open(filePath);
        if (openError)
            continue;

        application_information_t application_information = {};

        if (!read_exact(app, &application_information, sizeof(application_information_t)))
            continue;

        if (application_information.menu_location != app_location)
            continue;

        bool versionMatches = external_app_is_compatible(application_information);

        GridItemEx gridItem = {};
        gridItem.text = reinterpret_cast<char*>(&application_information.app_name[0]);

        if (versionMatches) {
            gridItem.color = Color((uint16_t)application_information.icon_color);

            auto dyn_bmp = DynamicBitmap<16, 16>{application_information.bitmap_data};
            gridItem.bitmap = dyn_bmp.bitmap();
            bitmaps.push_back(std::move(dyn_bmp));

            gridItem.on_select = [&nav, app_location, filePath]() {
                if (!run_external_app(nav, filePath)) {
                    nav.display_modal("Error", "The .ppma file in your " + apps_dir.string() + "\nfolder can't be read. Please\nupdate your SD Card content.");
                }
            };

            gridItem.desired_position = application_information.desired_menu_position;
        } else {
            gridItem.color = Theme::getInstance()->fg_light->foreground;

            gridItem.bitmap = &bitmap_sd_card_error;

            gridItem.on_select = [&nav]() {
                nav.display_modal("Error", "The .ppma file in your " + apps_dir.string() + "\nfolder is outdated. Please\nupdate your SD Card content.");
            };

            gridItem.desired_position = application_information.desired_menu_position;
        }

        external_apps.push_back(gridItem);
    }

    for (const auto& entry : std::filesystem::directory_iterator(apps_dir, u"*.ppmp")) {
        auto filePath = apps_dir / entry.path();
        File app;

        auto openError = app.open(filePath);
        if (openError)
            continue;

        standalone_application_information_t application_information = {};

        if (!read_exact(app, &application_information, sizeof(standalone_application_information_t)))
            continue;

        if (application_information.menu_location != app_location)
            continue;

        if (application_information.header_version > CURRENT_STANDALONE_APPLICATION_API_VERSION)
            continue;

        GridItemEx gridItem = {};
        gridItem.text = reinterpret_cast<char*>(&application_information.app_name[0]);

        gridItem.color = Color((uint16_t)application_information.icon_color);

        auto dyn_bmp = DynamicBitmap<16, 16>{application_information.bitmap_data};
        gridItem.bitmap = dyn_bmp.bitmap();
        bitmaps.push_back(std::move(dyn_bmp));

        gridItem.on_select = [&nav, app_location, filePath]() {
            if (!run_standalone_app(nav, filePath)) {
                nav.display_modal("Error", "The .ppmp file in your " + apps_dir.string() + "\nfolder can't be read. Please\nupdate your SD Card content.");
            }
        };

        gridItem.desired_position = -1;  // No desired position support for standalone apps yet

        external_apps.push_back(gridItem);
    }

    return external_apps;
}

/* static */ bool ExternalItemsMenuLoader::run_external_app(ui::NavigationView& nav, std::filesystem::path filePath) {
    externalAppEntry_t entry = nullptr;
    if (!prepare_external_app(filePath, entry))
        return false;

    entry(nav);
    return true;
}

// TODO: implement baseband image support
/* static */ bool ExternalItemsMenuLoader::run_standalone_app(ui::NavigationView& nav, std::filesystem::path filePath) {
    File app;

    auto openError = app.open(filePath);
    if (openError)
        return false;

    auto app_image = reinterpret_cast<uint8_t*>(portapack::memory::map::local_sram_0.base());

    // read file in 512 byte chunks
    for (size_t file_read_index = 0; file_read_index < app.size(); file_read_index += std::filesystem::max_file_block_size) {
        auto bytes_to_read = std::filesystem::max_file_block_size;
        if (file_read_index + std::filesystem::max_file_block_size > app.size())
            bytes_to_read = app.size() - file_read_index;

        auto readResult = app.read(&app_image[file_read_index], bytes_to_read);
        if (!readResult)
            return false;

        if (readResult.value() < std::filesystem::max_file_block_size)
            break;
    }

    for (size_t file_read_index = 0; file_read_index < app.size() / 4; file_read_index++) {
        uint32_t* ptr = reinterpret_cast<uint32_t*>(&app_image[file_read_index * 4]);

        if (*ptr >= 0xADB10000 && *ptr < (0xADB10000 + 64 * 1024)) {
            *ptr = *ptr - 0xADB10000 + (uint32_t)app_image;
        }
    }

    nav.push<StandaloneView>(app_image);
    return true;
}

// TODO: implement baseband image support
/* static */ bool ExternalItemsMenuLoader::run_module_app(ui::NavigationView& nav, uint8_t* app_image, size_t app_size) {
    for (size_t file_read_index = 0; file_read_index < app_size / 4; file_read_index++) {
        uint32_t* ptr = reinterpret_cast<uint32_t*>(&app_image[file_read_index * 4]);

        if (*ptr >= 0xADB10000 && *ptr < (0xADB10000 + 64 * 1024)) {
            *ptr = *ptr - 0xADB10000 + (uint32_t)app_image;
        }
    }

    nav.push<StandaloneView>(app_image);
    return true;
}

}  // namespace ui
