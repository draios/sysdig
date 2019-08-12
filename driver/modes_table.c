/*

Copyright (c) 2013-2019 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#include "ppm_events_public.h"

const struct ppm_name_value chmod_mode[] = {
    {"S_IXOTH", PPM_S_IXOTH},
    {"S_IWOTH", PPM_S_IWOTH},
    {"S_IROTH", PPM_S_IROTH},
    {"S_IXGRP", PPM_S_IXGRP},
    {"S_IWGRP", PPM_S_IWGRP},
    {"S_IRGRP", PPM_S_IRGRP},
    {"S_IXUSR", PPM_S_IXUSR},
    {"S_IWUSR", PPM_S_IWUSR},
    {"S_IRUSR", PPM_S_IRUSR},
    {"S_ISVTX", PPM_S_ISVTX},
    {"S_ISGID", PPM_S_ISGID},
    {"S_ISUID", PPM_S_ISUID},
    {0, 0},
};
