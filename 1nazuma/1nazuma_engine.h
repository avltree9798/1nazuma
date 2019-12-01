//
//  1nazuma_engine.h
//  1nazuma
//
//  Created by Anthony Viriya on R 1/12/01.
//  Copyright © Reiwa 1 Jake James. All rights reserved.
//

#ifndef _nazuma_engine_h
#define _nazuma_engine_h

#include <stdio.h>
#include <mach/mach_types.h>

int start_inazuma_engine(mach_port_t tfp0);
void exec(const char* path, int argc, ...);

#endif /* _nazuma_engine_h */
