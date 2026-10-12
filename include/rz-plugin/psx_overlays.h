#pragma once

#include <rz_core.h>
#include <retdec/loader/loader/psx_overlay_image.h>

namespace retdec { namespace rzplugin {

std::shared_ptr<const common::PsxMemoryContext> psxOverlaySnapshot(const RzCore* core);
void clearPsxOverlayState(RzCore* core);

} }
