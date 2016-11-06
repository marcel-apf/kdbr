/*
 * Kernel-based shared networking driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright 2016 Red Hat, Inc.
 * Copyright 2016 Oracle
 *
 * Authors:
 *   Marcel Apfelbaum <marcel@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */
#include <linux/module.h>

MODULE_AUTHOR("Marcel Apfelbaum");
MODULE_LICENSE("GPL");

static int shnet_init(void) 
{ 
    pr_info("shnet driver loaded\n"); 
    return 0; 
} 
EXPORT_SYMBOL_GPL(shnet_init);

static void shnet_exit(void) 
{
    pr_info("shnet driver unloaded\n"); 
} 
EXPORT_SYMBOL_GPL(shnet_exit);

module_init(shnet_init); 
module_exit(shnet_exit);


