//
// Created by Aubin Birba on 2023-11-07.
//

#ifndef FHE_CRYPTOGRAPH_HELPERS_H
#define FHE_CRYPTOGRAPH_HELPERS_H
#include "iostream"

#define PBSTR "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
#define PBWIDTH 60
//#define DEBUG


namespace helpers {
    void printProgress(double percentage) {
        int val = (int) (percentage * 100);
        int lpad = (int) (percentage * PBWIDTH);
        int rpad = PBWIDTH - lpad;
        printf("\r%3d%% [%.*s%*s]", val, lpad, PBSTR, rpad, "");
        fflush(stdout);
    }


}

#endif //FHE_CRYPTOGRAPH_HELPERS_H
