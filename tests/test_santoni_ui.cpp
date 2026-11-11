/* Execute the real HID timer/entry points and panel converter with host I/O. */
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using UInt32 = uint32_t;
struct OSObject {};
struct IOTimerEventSource {
    unsigned rearmed = 0, delay = 0;
    void setTimeoutMS(unsigned value) { rearmed++; delay = value; }
};
static unsigned key_count, key_usage, key_down, waits, interrupt_on_wait;
static bool gSweetPhysicalInput;
static const UInt32 kHIDUsage_Csmr_Power = 0x30, kHIDUsage_Csmr_Menu = 0x40;
static const UInt32 kHIDUsage_Csmr_VolumeIncrement = 0xe9, kHIDUsage_Csmr_VolumeDecrement = 0xea;
#define SWEET_TOUCH_FINGERS 10
#define NSEC_PER_MSEC 1000000
struct Touch { int id; bool down; int x, y; };
struct SweetHIDTouch {
    bool clients = true;
    std::vector<Touch> events;
    bool hasClients() const { return clients; }
    void touch(int id, bool down, int x, int y) { events.push_back({id, down, x, y}); }
};
struct SweetHIDButtons : OSObject {
    UInt32 fTestSecs = 5, fTestCount = 0;
    bool clients = true;
    bool hasClients() const { return clients; }
    void key(UInt32 usage, bool down) { key_count++; key_usage = usage; key_down = down; }
    static void testFired(OSObject *, IOTimerEventSource *);
};
static SweetHIDButtons *gSweetButtons;
static SweetHIDTouch *gSweetTouch;
static void IOLog(const char *, ...) {}
static void delay_for_interval(unsigned, unsigned)
{
    if (++waits == interrupt_on_wait) gSweetPhysicalInput = true;
}
static unsigned barriers;
struct AppleCLCD {
    uint32_t fBpp = 3, fPanelStride, fRowBytes, fWidth, fHeight;
    uintptr_t fPanelVA, fPixels;
    void blitPanel();
};
#include "santoni_ui_actual.h"

#define CHECK(expr) do { if (!(expr)) { \
    std::fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #expr); std::exit(1); \
} } while (0)

static void timer_quiet_without_client()
{
    SweetHIDButtons buttons; SweetHIDTouch touch; IOTimerEventSource timer;
    gSweetTouch = &touch; touch.clients = false;
    for (unsigned i = 0; i < 50; i++) SweetHIDButtons::testFired(&buttons, &timer);
    CHECK(key_count == 0 && touch.events.empty() && buttons.fTestCount == 0);
    CHECK(timer.rearmed == 50);
}

static void timer_stops_after_four_swipes()
{
    SweetHIDButtons buttons; SweetHIDTouch touch; IOTimerEventSource timer;
    gSweetTouch = &touch;
    for (unsigned i = 0; i < 100; i++) SweetHIDButtons::testFired(&buttons, &timer);
    unsigned presses = 0, releases = 0;
    for (const auto &event : touch.events) {
        if (event.down && event.y == 1270) presses++;
        if (!event.down) releases++;
    }
    CHECK(presses == 4 && releases == 4);
    CHECK(key_count == 0 && buttons.fTestCount == 4 && timer.rearmed == 3);
}

static void timer_stops_on_physical_touch()
{
    SweetHIDButtons buttons; SweetHIDTouch touch; IOTimerEventSource timer;
    gSweetTouch = &touch;
    sweet_hid_touch(0, 1, 123, 456);
    SweetHIDButtons::testFired(&buttons, &timer);
    CHECK(touch.events.size() == 1 && touch.events[0].id == 0);
    CHECK(key_count == 0 && timer.rearmed == 0);
}

static void timer_stops_on_physical_key()
{
    SweetHIDButtons buttons; SweetHIDTouch touch; IOTimerEventSource timer;
    gSweetButtons = &buttons; gSweetTouch = &touch;
    sweet_hid_key(2, 1);
    CHECK(key_count == 1 && key_usage == 0xea && key_down == 1);
    SweetHIDButtons::testFired(&buttons, &timer);
    CHECK(key_count == 1 && touch.events.empty() && timer.rearmed == 0);
}

static void timer_interrupted_swipe_releases()
{
    SweetHIDButtons buttons; SweetHIDTouch touch; IOTimerEventSource timer;
    gSweetTouch = &touch; interrupt_on_wait = 2;
    SweetHIDButtons::testFired(&buttons, &timer);
    CHECK(touch.events.size() == 3 && touch.events.front().down);
    CHECK(touch.events.back().id == 9 && !touch.events.back().down);
    CHECK(touch.events.back().y == 1050 && key_count == 0 && timer.rearmed == 0);
}

static void key_usages()
{
    SweetHIDButtons buttons; gSweetButtons = &buttons;
    sweet_hid_key(1, 1);
    CHECK(key_count == 1 && key_usage == 0xe9 && key_down == 1);
    sweet_hid_key(1, 0);
    CHECK(key_count == 2 && key_usage == 0xe9 && key_down == 0);
    sweet_hid_key(2, 1);
    CHECK(key_count == 3 && key_usage == 0xea && key_down == 1);
    sweet_hid_key(2, 0);
    CHECK(key_count == 4 && key_usage == 0xea && key_down == 0);
    sweet_hid_key(-1, 1); sweet_hid_key(4, 1);
    CHECK(key_count == 4);
    sweet_hid_key(0, 1);
    CHECK(key_count == 5 && key_usage == 0x30 && key_down == 1);
    sweet_hid_key(0, 0);
    CHECK(key_count == 6 && key_usage == 0x30 && key_down == 0);
}

static void buttons_ready_only_with_clients()
{
#ifdef SANTONI_HOST_HAS_BUTTON_READY
    CHECK(!sweet_hid_buttons_ready());
    SweetHIDButtons buttons; gSweetButtons = &buttons;
    buttons.clients = false;
    CHECK(!sweet_hid_buttons_ready());
    buttons.clients = true;
    CHECK(sweet_hid_buttons_ready());
#else
    CHECK(false);
#endif
}

static void panel_case(unsigned width, unsigned height, unsigned pad, unsigned offset)
{
    unsigned stride = 3 * width + pad, src_stride = (4 * width + 19) & ~3u;
    std::vector<uint32_t> source((src_stride * height + 3) / 4);
    uint32_t rng = 0x97531;
    for (auto &pixel : source) { rng = rng * 1664525u + 1013904223u; pixel = rng; }
    std::vector<uint8_t> dest(32 + offset + stride * height, 0xa5), expected = dest;
    auto *src = reinterpret_cast<const uint8_t *>(source.data());
    for (unsigned y = 0; y < height; y++) {
        for (unsigned x = 0; x < width; x++) {
            for (unsigned c = 0; c < 3; c++)
                expected[16 + offset + y * stride + x * 3 + c] = src[y * src_stride + x * 4 + c];
        }
    }
    AppleCLCD fb;
    fb.fWidth = width; fb.fHeight = height;
    fb.fPanelStride = stride; fb.fRowBytes = src_stride;
    fb.fPanelVA = reinterpret_cast<uintptr_t>(dest.data() + 16 + offset);
    fb.fPixels = reinterpret_cast<uintptr_t>(source.data());
    unsigned before = barriers;
    fb.blitPanel();
    CHECK(dest == expected && barriers == before + 1);
}

static void panel_native() { panel_case(720, 1280, 0, 0); }
static void panel_boundaries()
{
    for (unsigned w = 1; w <= 33; w++)
        for (unsigned pad = 0; pad < 4; pad++)
            for (unsigned off = 0; off < 4; off++) panel_case(w, 7, pad, off);
}

int main(int argc, char **argv)
{
    const struct { const char *name; void (*test)(); } tests[] = {
        {"timer_quiet_without_client", timer_quiet_without_client},
        {"timer_stops_after_four_swipes", timer_stops_after_four_swipes},
        {"timer_stops_on_physical_touch", timer_stops_on_physical_touch},
        {"timer_stops_on_physical_key", timer_stops_on_physical_key},
        {"timer_interrupted_swipe_releases", timer_interrupted_swipe_releases},
        {"key_usages", key_usages},
        {"buttons_ready_only_with_clients", buttons_ready_only_with_clients},
        {"panel_native", panel_native},
        {"panel_boundaries", panel_boundaries},
    };
    if (argc != 2) return 2;
    for (const auto &test : tests) {
        if (!std::strcmp(argv[1], "--list")) std::puts(test.name);
        else if (!std::strcmp(argv[1], test.name)) { test.test(); return 0; }
    }
    return std::strcmp(argv[1], "--list") ? 2 : 0;
}
