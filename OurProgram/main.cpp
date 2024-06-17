#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include "Memory.h"

void DMA()
{
    if (!mem.Init("DayZ_x64.exe", false, false))
    {
        std::cerr << "Failed to initialize DMA" << std::endl;
        exit(1);
    }

    uintptr_t base = mem.GetBaseDaddy("DayZ_x64.exe");
    if (base == 0)
    {
        std::cerr << "Failed to get base address of DayZ_x64.exe" << std::endl;
        exit(1);
    }
    std::cout << "[+] Found Base Address for DayZ_x64.exe at 0x" << std::hex << base << std::dec << std::endl;
    size_t baseSize = mem.GetBaseSize("DayZ_x64.exe");
    std::cout << "[+] Found Base Size for DayZ_x64.exe at 0x" << std::hex << baseSize << std::dec << std::endl;

    // Define the pattern and mask for the "world" offset
    const char* worldPattern = "\x48\x8B\x05\x00\x00\x00\x00\x48\x8D\x54\x24\x00\x48\x8B\x48\x30";
    const char* worldMask = "xxx????xxxx?xxxx";

    // Use FindSignature to locate the pattern
    uint64_t worldPatternAddress = mem.FindSignature(worldPattern, worldMask, base, base + baseSize);
    if (worldPatternAddress == 0)
    {
        std::cerr << "Failed to find world offset pattern" << std::endl;
        return;
    }

    // Read the relative address from the pattern
    int32_t WrelativeOffset = 0;
    if (!mem.Read(worldPatternAddress + 3, &WrelativeOffset, sizeof(WrelativeOffset)))
    {
        std::cerr << "Failed to read relative offset for world address" << std::endl;
        return;
    }

    // Calculate the absolute address
    uintptr_t worldOffset = worldPatternAddress + WrelativeOffset + 7; // 7 is the size of the instruction
    std::cout << "Calculated world offset: 0x" << std::hex << worldOffset << std::dec << std::endl;

    // Define patterns and masks for additional offsets
    const char* bulletListPattern = "\x48\x8B\x83\x00\x00\x00\x00\x49\x8B\xCF\x48\x03\x0C\xF8";
    const char* bulletListMask = "xxx????xxxxxxx";

    const char* nearEntListPattern = "\x48\x8B\x83\x00\x00\x00\x00\x49\x8B\x14\x06\x48\x3B\xD5";
    const char* nearEntListMask = "xxx????xxxxxxx";

    const char* farEntListPattern = "\x48\x8B\x83\x00\x00\x00\x00\x49\x8B\x0C\x06\x48\x3B\xCD\x74\x17\x80\xB9\x00\x00\x00\x00\x00\x75\x0E\x41\xB8\x00\x00\x00\x00\x0F\x28\xCE\xE8\x00\x00\x00\x00\xFF\xC6\x49\x83\xC6\x08\x3B\xB3\x00\x00\x00\x00\x7C\xCB";
    const char* farEntListMask = "xxx????xxxxxxxxxxx?????xxxx????xxxx????xxxxxxxx????xx";

    const char* cameraPattern = "\x4C\x8B\x83\x00\x00\x00\x00\x4C\x8B\x11\x48\x89\x70\x08";
    const char* cameraMask = "xxx????xxxxxxx";

    const char* localPlayerPattern = "\xE8\x00\x00\x00\x00\x48\x8B\xC8\xC7\x44\x24\x00\x00\x00\x00\x00\x4C\x8D\x0D\x00\x00\x00\x00";
    const char* localPlayerMask = "x????xxxxxx?????xxx????";

    const char* localOffsetPattern = "\xE8\x00\x00\x00\x00\x48\x8B\xC8\xC7\x44\x24\x00\x00\x00\x00\x00\x4C\x8D\x0D\x00\x00\x00\x00";
    const char* localOffsetMask = "x????xxxxxx?????xxx????";

    // Function to calculate offsets based on pattern and mask
    auto calculateOffset = [&](const char* pattern, const char* mask, size_t relativeOffsetPosition, size_t offsetSize) -> uintptr_t {
        uint64_t patternAddress = mem.FindSignature(pattern, mask, base, base + baseSize);
        if (patternAddress == 0)
        {
            std::cerr << "Failed to find pattern" << std::endl;
            return 0;
        }


        int32_t relativeOffset = 0;
        if (!mem.Read(patternAddress + relativeOffsetPosition, &relativeOffset, sizeof(relativeOffset)))
        {
            std::cerr << "Failed to read relative offset" << std::endl;
            return 0;
        }


        uintptr_t absoluteOffset = patternAddress + relativeOffset + offsetSize;
        std::cout << "Calculated offset: 0x" << std::hex << absoluteOffset << std::dec << std::endl;

        return absoluteOffset;
        };

    // Calculate additional offsets
    uintptr_t bulletListOffset = calculateOffset(bulletListPattern, bulletListMask, 3, 7); // Relative offset starts at byte 3 Instruction size: 7 bytes
    uintptr_t nearEntListOffset = calculateOffset(nearEntListPattern, nearEntListMask, 3, 7);
    uintptr_t farEntListOffset = calculateOffset(farEntListPattern, farEntListMask, 3, 7);
    uintptr_t cameraOffset = calculateOffset(cameraPattern, cameraMask, 3, 7);
    uintptr_t localPlayerOffset = calculateOffset(localPlayerPattern, localPlayerMask, 1, 5);
    uintptr_t localOffset = calculateOffset(localOffsetPattern, localOffsetMask, 1, 21); // Adjusted for the specific offset size

    // Define patterns and masks for camera-based offsets
    const char* viewMatrixPattern = "\xF3\x0F\x10\x40\x00\xF3\x0F\x10\x50\x00\xF3\x0F\x10\x58\x00";
    const char* viewMatrixMask = "xxxx?xxxx?xxxx?";

    const char* viewPortMatrixPattern = "\xF3\x0F\x11\x4E\x00\x66\x0F\x6E\xC1";
    const char* viewPortMatrixMask = "xxxx?xxxx";

    const char* viewProjectionPattern = "\x0F\x11\x86\x00\x00\x00\x00\x0F\x10\x44\x24\x00\x0F\x11\x86\x00\x00\x00\x00\x0F\x10\x44\x24\x00\x0F\x11\x86\x00\x00\x00\x00\x48\x8B\x06";
    const char* viewProjectionMask = "xxx????xxxx?xxx????xxxx?xxx????xxx";

    // Calculate camera-based offsets
    uintptr_t viewMatrixOffset = calculateOffset(viewMatrixPattern, viewMatrixMask, 4, 5);
    uintptr_t viewPortMatrixOffset = calculateOffset(viewPortMatrixPattern, viewPortMatrixMask, 4, 5);
    uintptr_t viewProjectionOffset = calculateOffset(viewProjectionPattern, viewProjectionMask, 3, 7);

    // Write the offsets to a file
    std::ofstream outFile("Offsets.txt");
    if (!outFile)
    {
        std::cerr << "Failed to open Offsets.txt for writing" << std::endl;
        return;
    }

    outFile << "Base address of DayZ_x64.exe: 0x" << std::hex << base << std::dec << std::endl;
    outFile << "World offset: 0x" << std::hex << worldOffset << std::dec << std::endl;
    outFile << "BulletList offset: 0x" << std::hex << bulletListOffset << std::dec << std::endl;
    outFile << "NearEntList offset: 0x" << std::hex << nearEntListOffset << std::dec << std::endl;
    outFile << "FarEntList offset: 0x" << std::hex << farEntListOffset << std::dec << std::endl;
    outFile << "Camera offset: 0x" << std::hex << cameraOffset << std::dec << std::endl;
    outFile << "LocalPlayer offset: 0x" << std::hex << localPlayerOffset << std::dec << std::endl;
    outFile << "LocalOffset offset: 0x" << std::hex << localOffset << std::dec << std::endl;
    outFile << "ViewMatrix offset: 0x" << std::hex << viewMatrixOffset << std::dec << std::endl;
    outFile << "ViewPortMatrix offset: 0x" << std::hex << viewPortMatrixOffset << std::dec << std::endl;
    outFile << "ViewProjection offset: 0x" << std::hex << viewProjectionOffset << std::dec << std::endl;

    outFile.close();

    std::cout << "Offsets logged to Offsets.txt" << std::endl;
}





int main()
{
    try
    {
        DMA();
        std::cout << "Dumping Complete Check the output.txt" << std::endl;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    std::cout << "Made By F0RSV1NNA" << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(30));
    return 0;
}
