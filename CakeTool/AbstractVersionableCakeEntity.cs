using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool;

public abstract class AbstractVersionableCakeEntity
{
    // Main header stuff
    // v6.7/6.8 = 20
    // v8.1 = 21
    // v8.2/v8.3 = 22
    // v8.7 = 23
    // v9.1/v9.2 = 24
    // v9.3 = 25
    public byte VersionMajor { get; set; }
    public byte VersionMinor { get; set; }

    public bool IsVersion(byte versionMajor, byte versionMinor)
    {
        return VersionMajor == versionMajor && VersionMinor == versionMinor;
    }

    public bool IsAtLeastVersion(byte versionMajor, byte versionMinor = 0)
    {
        if (VersionMajor < versionMajor)
            return false;

        return VersionMajor > versionMajor || (VersionMajor == versionMajor && VersionMinor >= versionMinor);
    }
}
