"use strict";

//**************************************************************************
// LinuxKernel.js:
//
// Extension for Linux Kernel debugging.  This extension is intended to provide the functionality
// of the most commonly used commands within the Linux crash utility for understanding kernel
// mode crashes.
//

delete Object.prototype.toString;
var __kernelInfo = null;

//**************************************************************************
// Global Configuration:
//

//
// __permitVmCoreInfo: allows usage of VMCOREINFO as exposed through <session>.Diagnostics.VMCoreInfo
//                     to acquire symbol addresses and field offsets necessary to read certain kernel
//                     information.  If this is false, kernel symbols are required.
//
var __permitVmCoreInfo = true;

//**************************************************************************
// Utility:
//

// ListTraversal
//
// Iterates elements of a kernel list.
//
class __ListTraversal
{
    constructor(listHead, instTyName, instFldName)
    {
        this.__listHead = listHead;
        this.__instTyName = instTyName;
        this.__instTy = host.getModuleType("vmlinux", instTyName);
        this.__instFldName = instFldName;
        this.__instFld = this.__instTy.fields[instFldName];
        this.__instFldOffset = this.__instFld.offset;
    }

    *[Symbol.iterator]()
    {
        var ptr = this.__listHead.next;
        var startPtr = ptr;
        var returnedFirst = false;

        while(!ptr.isNull)
        {
            if (returnedFirst)
            {
                if (ptr.address.compareTo(startPtr.address) == 0 ||
                    ptr.address.compareTo(this.__listHead.address) == 0)
                {
                    break;
                }
            }

            yield host.createTypedObject(ptr.address.subtract(this.__instFldOffset), this.__instTy);

            ptr = ptr.next;
            returnedFirst = true;
        }
    }
}

// KListTraversal:
//
// Iterates elements of a kernel KLIST
//
class __KListTraversal
{
    constructor(klist, instTyName, instFldName)
    {
        this.__klist = klist;
        this.__klistInfo = __getKernelInfo().klistInfo;
        this.__instTyName = instTyName;
        this.__instTy = host.getModuleType("vmlinux", instTyName);
        this.__instFldName = instFldName;
        this.__instFld = this.__instTy.fields[instFldName];
        this.__instFldOffset = this.__instFld.offset;
    }

    *[Symbol.iterator]()
    {
        var ptr = this.__klist.k_list.next;
        var startPtr = ptr;
        var returnedFirst = false;

        while(!ptr.isNull)
        {
            if (returnedFirst)
            {
                if (ptr.address.compareTo(startPtr.address) == 0 ||
                    ptr.address.compareTo(this.__klist.k_list.address) == 0)
                {
                    break;
                }
            }

            yield host.createTypedObject(ptr.address.subtract(this.__instFldOffset + this.__klistInfo.klistOfNodeOffset), this.__instTy);

            ptr = ptr.next;
            returnedFirst = true;
        }
    }
}

// RbTraversal
//
// Iterates elements of a kernel red-black tree given by rb_node
//
class __RbTraversal
{
    constructor(rootRb, instTyName, instFldName)
    {
        this.__rootRb = rootRb;
        this.__instTyName = instTyName;
        this.__instTy = host.getModuleType("vmlinux", instTyName);
        this.__instFldName = instFldName;
        this.__instFld = this.__instTy.fields[instFldName];
        this.__instFldOffset = this.__instFld.offset;
    }

    *[Symbol.iterator]()
    {
        var srch = [];
        var cur = this.__rootRb;
        var lptr = this.__rootRb.rb_left;
        if (!lptr.isNull)
        {
            srch.push(lptr);
        }
        var rptr = this.__rootRb.rb_right;
        if (!rptr.isNull)
        {
            srch.push(rptr);
        }

        while(srch.length > 0)
        {
            var curRbPtr = srch.shift();
            yield host.createTypedObject(curRbPtr.address.subtract(this.__instFldOffset), this.__instTy);

            var curRb = curRbPtr.dereference();
            lptr = curRb.rb_left;
            if (!lptr.isNull)
            {
                srch.push(lptr);
            }
            rptr = curRb.rb_right;
            if (!rptr.isNull)
            {
                srch.push(rptr);
            }
        }
    }
}

function __pathCombine(p1, p2)
{
    if (p1.endsWith("/") && p2.startsWith("/"))
    {
        return p1 + p2.slice(1);
    }
    else if (p1.endsWith("/") || p2.startsWith("/"))
    {
        return p1 + p2;
    }
    else
    {
        return p1 + "/" + p2;
    }
}

//**************************************************************************
// Extension:
//

// KernelInfo:
//
// Represents kernel information that we cache within this script
//
class __KernelInfo
{
    constructor(session)
    {
        this.__session = session;
        try
        {
            this.__vmcoreinfo = session.Diagnostics.VMCoreInfo;
        }
        catch(exc)
        {
            this.__vmcoreinfo = null;
        }

        this.__printkLogInfo = null;
        this.__namespaceInfo = null;
        this.__fileSystemInfo = null;
        this.__deviceInfo = null;
        this.__kernFsInfo = null;
        this.__klistInfo = null;
    }

    get printKLogInfo()
    {
        if (this.__printkLogInfo == null)
        {
            //
            // @TODO: host.getModuleSymbol() is still a tad slow on kernel symbols...
            //
            
            //
            // The entire printk subsystem was reworked in 5.10.x kernels.  We need to be able
            // to deal with both variants of the printk system depending on what we are targeting.
            //
            // In addition, we may or may not have a VMCOREINFO from which to get data.  We may or may not 
            // have kernel symbols from which to get data.  We should be able to deal with either kernel
            // from either a VMCOREINFO *OR* kernel symbols.  Post-mortem dumps will have the VMCOREINFO.
            // Live targets (e.g.: EXDI) will not -- but may have kernel symbols.
            //
            // In a pre-5.10 kernel, the following entries are defined in the VMCOREINFO:
            //
            //    SYMBOL(log_buf)=ffff000008de2fc8
            //    SYMBOL(log_buf_len)=ffff000008de2fc0
            //    SYMBOL(log_first_idx)=ffff000008ec081c
            //    SYMBOL(clear_idx)=ffff000008ec0828
            //    SYMBOL(log_next_idx)=ffff000008ec0818
            //    SIZE(printk_log)=16
            //    OFFSET(printk_log.ts_nsec)=0
            //    OFFSET(printk_log.len)=8
            //    OFFSET(printk_log.text_len)=10
            //    OFFSET(printk_log.dict_len)=12
            //
            // In a 5.10 (or later) kernel, the following entries are defined in the VMCOREINFO:
            //
            //    SYMBOL(prb)=ffffffff91473580
            //    SYMBOL(printk_rb_static)=ffffffff914735a0
            //    SYMBOL(clear_seq)=ffffffff91aeba70
            //    SIZE(printk_ringbuffer)=80
            //    OFFSET(printk_ringbuffer.desc_ring)=0
            //    OFFSET(printk_ringbuffer.text_data_ring)=40
            //    OFFSET(printk_ringbuffer.fail)=72
            //    SIZE(prb_desc_ring)=40
            //    OFFSET(prb_desc_ring.count_bits)=0
            //    OFFSET(prb_desc_ring.descs)=8
            //    OFFSET(prb_desc_ring.infos)=16
            //    OFFSET(prb_desc_ring.head_id)=24
            //    OFFSET(prb_desc_ring.tail_id)=32
            //    SIZE(prb_desc)=24
            //    OFFSET(prb_desc.state_var)=0
            //    OFFSET(prb_desc.text_blk_lpos)=8
            //    SIZE(prb_data_blk_lpos)=16
            //    OFFSET(prb_data_blk_lpos.begin)=0
            //    OFFSET(prb_data_blk_lpos.next)=8
            //    SIZE(printk_info)=88
            //    OFFSET(printk_info.seq)=0
            //    OFFSET(printk_info.ts_nsec)=8
            //    OFFSET(printk_info.text_len)=16
            //    OFFSET(printk_info.caller_id)=20
            //    OFFSET(printk_info.dev_info)=24
            //    SIZE(dev_printk_info)=64
            //    OFFSET(dev_printk_info.subsystem)=0
            //    LENGTH(printk_info_subsystem)=16
            //    OFFSET(dev_printk_info.device)=16
            //    LENGTH(printk_info_device)=48
            //    SIZE(prb_data_ring)=32
            //    OFFSET(prb_data_ring.size_bits)=0
            //    OFFSET(prb_data_ring.data)=8
            //    OFFSET(prb_data_ring.head_lpos)=16
            //    OFFSET(prb_data_ring.tail_lpos)=24
            //    SIZE(atomic_long_t)=8
            //    OFFSET(atomic_long_t.counter)=0
            //
            // If we have a VMCOREINFO, the key symbol we are looking for is either "vmlinux!log_buf"
            // or "vmlinux!prb".  We are either going to find this in the VMCOREINFO (and know which variant)
            // or we are going to find this in symbols.  VMCOREINFO is preferred.
            //
            var usedVmCoreInfo = false;
            if (this.__vmcoreinfo && __permitVmCoreInfo)
            {
                if (this.__vmcoreinfo.Symbols.log_buf !== undefined)
                {
                    usedVmCoreInfo = true;

                    //
                    // It's a pre 5.10 kernel.  Go dig out the information we need.
                    //
                    this.__printkLogInfo =
                    {
                        pre_5_10_kernel: true,
                        log_buf_addr: this.__vmcoreinfo.Symbols.log_buf,
                        log_buf_len_addr: this.__vmcoreinfo.Symbols.log_buf_len,
                        log_first_idx_addr: this.__vmcoreinfo.Symbols.log_first_idx,
                        log_next_idx_addr: this.__vmcoreinfo.Symbols.log_next_idx,
                        printk_log_size: this.__vmcoreinfo.Sizes.printk_log,
                        printk_log_ts_nsec_offset: this.__vmcoreinfo.Offsets.printk_log.ts_nsec,
                        printk_log_len_offset: this.__vmcoreinfo.Offsets.printk_log.len,
                        printk_log_text_len_offset: this.__vmcoreinfo.Offsets.printk_log.text_len,
                        printk_log_dict_len_offset: this.__vmcoreinfo.Offsets.printk_log.dict_len
                    };

                    //
                    // If we have symbols, we can give more information than is available from
                    // VMCOREINFO based extraction.
                    //
                    this.__printkLogInfo.printkLogType = host.getModuleType("vmlinux", "printk_log");
                }
                else if (this.__vmcoreinfo.Symbols.prb !== undefined)
                {
                    usedVmCoreInfo = true;

                    //
                    // It's a 5.10+ kernel.  Go dig out the information we need.
                    //

                    //
                    // @TODO: This should *NOT* be hard coded to 64-bits.
                    //
                    var three = new host.Int64(3);
                    var stateFlagsMask = three.bitwiseShiftLeft(62);
                    var idMask = stateFlagsMask.bitwiseNot();

                    this.__printkLogInfo =
                    {
                        pre_5_10_kernel: false,
                        prb_addr: this.__vmcoreinfo.Symbols.prb,
                        printk_ringbuffer_size: this.__vmcoreinfo.Sizes.printk_ringbuffer,
                        prb_desc_ring_size: this.__vmcoreinfo.Sizes.prb_desc_ring,
                        prb_desc_size: this.__vmcoreinfo.Sizes.prb_desc,
                        prb_data_ring_size: this.__vmcoreinfo.Sizes.prb_data_ring,
                        printk_info_size: this.__vmcoreinfo.Sizes.printk_info,
                        atomic_long_t_size: this.__vmcoreinfo.Sizes.atomic_long_t,
                        prb_data_blk_lpos_size: this.__vmcoreinfo.Sizes.prb_data_blk_lpos,
                        printk_ringbuffer_offsets: this.__vmcoreinfo.Offsets.printk_ringbuffer,
                        printk_info_offsets: this.__vmcoreinfo.Offsets.printk_info,
                        prb_desc_ring_offsets: this.__vmcoreinfo.Offsets.prb_desc_ring,
                        prb_data_ring_offsets: this.__vmcoreinfo.Offsets.prb_data_ring,
                        prb_desc_offsets: this.__vmcoreinfo.Offsets.prb_desc,
                        prb_data_blk_lpos_offsets: this.__vmcoreinfo.Offsets.prb_data_blk_lpos,
                        stateFlagsMask: stateFlagsMask,
                        stateFlagsShift: 62,
                        idMask: idMask
                    };

                    //
                    // If we have symbols, we can give more information than is available
                    // from VMCOREINFO based extraction.
                    //
                    this.__printkLogInfo.printkInfoType = host.getModuleType("vmlinux", "printk_info");
                }
            }

            if (!usedVmCoreInfo)
            {
                // Pre 5.10, *printk_log* is the entry type.
                // 5.10 and later, it's *printk_info*
                //
                // Depending on which symbol we see in the kernel, we will trigger a different variation of the
                // projecting the kernel log outwards.
                // 
                var printkLogType = host.getModuleType("vmlinux", "printk_log");
                var printkInfoType = host.getModuleType("vmlinux", "printk_info");

                if (printkLogType == null)
                {
                    //
                    // 5.10+ kernel
                    //
                    var printkRingBufferType = host.getModuleType("vmlinux", "printk_ringbuffer");
                    var prbDescRingType = host.getModuleType("vmlinux", "prb_desc_ring");
                    var prbDescType = host.getModuleType("vmlinux", "prb_desc");
                    var prbDataRingType = host.getModuleType("vmlinux", "prb_data_ring");
                    var prbDataBlkLposType = host.getModuleType("vmlinux", "prb_data_blk_lpos");
                    var atomicLongTType = host.getModuleType("vmlinux", "atomic_long_t");

                    //
                    // @TODO: This should *NOT* be hard coded to 64-bits.
                    //
                    var three = new host.Int64(3);
                    var stateFlagsMask = three.bitwiseShiftLeft(62);
                    var idMask = stateFlagsMask.bitwiseNot();

                    this.__printkLogInfo =
                    {
                        pre_5_10_kernel: false,
                        printkInfoType: printkInfoType,
                        prb_addr: host.getModuleSymbolAddress("vmlinux", "prb"),
                        printk_ringbuffer_size: printkRingBufferType.size,
                        prb_desc_ring_size: prbDescRingType.size,
                        prb_desc_size: prbDescType.size,
                        prb_data_ring_size: prbDataRingType.size,
                        printk_info_size: printkInfoType.size,
                        atomic_long_t_size: atomicLongTType.size,
                        prb_data_blk_lpos_size: prbDataBlkLposType.size,
                        printk_ringbuffer_offsets:
                        {
                            desc_ring: printkRingBufferType.fields.desc_ring.offset,
                            text_data_ring: printkRingBufferType.fields.text_data_ring.offset,
                            fail: printkRingBufferType.fields.fail.offset
                        },
                        printk_info_offsets:
                        {
                            seq: printkInfoType.fields.seq.offset,
                            ts_nsec: printkInfoType.fields.ts_nsec.offset,
                            text_len: printkInfoType.fields.text_len.offset,
                            caller_id: printkInfoType.fields.caller_id.offset,
                            dev_info: printkInfoType.fields.dev_info.offset
                        },
                        prb_desc_ring_offsets:
                        {
                            count_bits: prbDescRingType.fields.count_bits.offset,
                            descs: prbDescRingType.fields.descs.offset,
                            infos: prbDescRingType.fields.infos.offset,
                            head_id: prbDescRingType.fields.head_id.offset,
                            tail_id: prbDescRingType.fields.tail_id.offset,
                        },
                        prb_desc_offsets:
                        {
                            state_var: prbDescType.fields.state_var.offset,
                            text_blk_lpos: prbDescType.fields.text_blk_lpos.offset
                        },
                        prb_data_ring_offsets:
                        {
                            size_bits: prbDataRingType.fields.size_bits.offset,
                            data: prbDataRingType.fields.data.offset,
                            head_lpos: prbDataRingType.fields.head_lpos.offset,
                            tail_lpos: prbDataRingType.fields.tail_lpos.offset
                        },
                        prb_data_blk_lpos_offsets: 
                        {
                            begin: prbDataBlkLposType.fields.begin.offset,
                            next: prbDataBlkLposType.fields.next.offset,
                        },
                        stateFlagsMask: stateFlagsMask,
                        stateFlagsShift: 62,
                        idMask: idMask
                    };
                }
                else
                {

                    //
                    // 5.9- kernel
                    //
                    this.__printkLogInfo =
                    {
                        pre_5_10_kernel: true,
                        printkLogType: printkLogType,
                        log_buf_addr: host.getModuleSymbolAddress("vmlinux", "log_buf"),
                        log_buf_len_addr: host.getModuleSymbolAddress("vmlinux", "log_buf_len"),
                        log_first_idx_addr: host.getModuleSymbolAddress("vmlinux", "log_first_idx"),
                        log_next_idx_addr: host.getModuleSymbolAddress("vmlinux", "log_next_idx"),
                        printk_log_size: printkLogType.size,
                        printk_log_ts_nsec_offset: printkLogType.fields.ts_nsec.offset,
                        printk_log_len_offset: printkLogType.fields.len.offset,
                        printk_log_text_len_offset: printkLogType.fields.text_len.offset,
                        printk_log_dict_len_offset: printkLogType.fields.dict_len.offset
                    };
                }
            }
        }
        return this.__printkLogInfo;
    }

    get namespaceInfo()
    {
        if (this.__namespaceInfo == null)
        {
            //
            // @TODO: host.getModuleSymbol() is still a tad slow on kernel symbols...
            //
            var netNamespaceList = host.getModuleSymbol("vmlinux", "net_namespace_list");

            this.__namespaceInfo =
            {
                netNamespaceList: netNamespaceList
            };
        }
        return this.__namespaceInfo;
    }

    get fileSystemInfo()
    {
        if (this.__fileSystemInfo == null)
        {
            //
            // @TODO: host.getModuleSymbol() is still a tad slow on kernel symbols...
            //
            var superBlockList = host.getModuleSymbol("vmlinux", "super_blocks");

            this.__fileSystemInfo =
            {
                superBlockList: superBlockList
            };
        }
        return this.__fileSystemInfo;
    }

    get deviceInfo()
    {
        if (this.__deviceInfo == null)
        {
            //
            // @TODO: host.getModuleSymbol() is still a tad slow on kernel symbols...
            //
            var blockDevicesList = host.getModuleSymbol("vmlinux", "all_bdevs");

            var majorNames = host.getModuleSymbol("vmlinux", "major_names");
            var majorNamesTy = majorNames.targetType;
            var majorNamesEntryTy = majorNamesTy.baseType;
            var majorNamesCount = majorNamesTy.size / majorNamesEntryTy.size;

            var characterDevicesList = host.getModuleSymbol("vmlinux", "chrdevs");
            var characterDevicesTy = characterDevicesList.targetType;
            var characterDevicesEntryTy = characterDevicesTy.baseType;
            var characterDevicesCount = characterDevicesTy.size / characterDevicesEntryTy.size;

            this.__deviceInfo =
            {
                blockDevicesList: blockDevicesList,
                majorNames: majorNames,
                majorNamesCount: majorNamesCount,
                characterDevicesList: characterDevicesList,
                characterDevicesCount: characterDevicesCount
            };
        }
        return this.__deviceInfo;
    }

    get klistInfo()
    {
        if (this.__klistInfo == null)
        {
            var klistNodeType = host.getModuleType("vmlinux", "klist_node");
            var klistOfNodeOffset = klistNodeType.fields["n_node"].offset;

            this.__klistInfo = 
            {
                klistNodeType: klistNodeType,
                klistOfNodeOffset: klistOfNodeOffset
            };
        }
        return this.__klistInfo;
    }

    get kernFsInfo()
    {
        if (this.__kernFsInfo == null)
        {
            //
            // @TODO: host.getModuleSymbol() is still a tad slow on kernel symbols.
            //
            var systemKSet = host.getModuleSymbol("vmlinux", "system_kset");
            var node = systemKSet.kobj.sd.dereference();
            var parent = node.parent;
            while (!parent.isNull)
            {
                node = parent.dereference();
                parent = node.parent;
            }
            var subSysPrivateType = host.getModuleType("vmlinux", "subsys_private");
            var ksetType = host.getModuleType("vmlinux", "kset");
            var subSysOffset = subSysPrivateType.fields["subsys"].offset;
            var kobjOffset = ksetType.fields["kobj"].offset;

            var devicePrivateType = host.getModuleType("vmlinux", "device_private");


            this.__kernFsInfo =
            {
                root: node,
                subSysPrivateType: subSysPrivateType,
                devicePrivateType: devicePrivateType,
                ksetType: ksetType,
                subSysOffset: subSysOffset,
                kobjOffset: kobjOffset,
            }
        }
        return this.__kernFsInfo;
    }

    get perCpuInfo()
    {
        if (this.__perCpuInfo == null)
        {
            var perCpuStart = host.getModuleSymbolAddress("vmlinux", "__per_cpu_start");
            var perCpuEnd = host.getModuleSymbolAddress("vmlinux", "__per_cpu_end");
            var perCpuOffset = host.getModuleSymbol("vmlinux", "__per_cpu_offset");

            var ty = perCpuOffset.targetType;
            var baseTy = ty.baseType;
            var perCpuOffsetSize = ty.size / baseTy.size;
                 
            this.__perCpuInfo =
            {
                perCpuStart: perCpuStart,
                perCpuEnd: perCpuEnd,
                perCpuOffset: perCpuOffset,
                perCpuOffsetSize: perCpuOffsetSize
            }
        }
        return this.__perCpuInfo;
    }

    get timerInfo()
    {
        if (this.__timerInfo == null)
        {
            var jiffies = host.getModuleSymbol("vmlinux", "jiffies_64");
            var timerBases = host.getModuleSymbol("vmlinux", "timer_bases");
            var timerListType = host.getModuleType("vmlinux", "timer_list");
            var entryField = timerListType.fields["entry"];
            var entryOffset = entryField.offset;
            var hrtimerBases = host.getModuleSymbol("vmlinux", "hrtimer_bases");
            var hrtimerType = host.getModuleType("vmlinux", "hrtimer");
            var nodeField = hrtimerType.fields["node"];
            var nodeOffset = nodeField.offset;

            this.__timerInfo =
            {
                jiffies: jiffies,
                timerBases: timerBases,
                timerListType: timerListType,
                entryOffset: entryOffset,
                hrtimerBases: hrtimerBases,
                hrtimerType: hrtimerType,
                nodeOffset: nodeOffset
            }

        }
        return this.__timerInfo;
    }

    get pointerSize()
    {
        // @TODO: This should *NOT* be hard coded to 8.
        return 8;
    }

}

function __getKernelInfo()
{
    if (__kernelInfo == null)
    {
        __kernelInfo = new __KernelInfo(host.currentSession);
    }
    return __kernelInfo;
}

var __facilityNames = [
    "LOG_KERN",                 // 0
    "LOG_USER",                 // 1
    "LOG_MAIL",                 // 2
    "LOG_DAEMON",               // 3
    "LOG_AUTH",                 // 4
    "LOG_SYSLOG",               // 5
    "LOG_LPR",                  // 6
    "LOG_NEWS",                 // 7
    "LOG_UUCP",                 // 8
    "LOG_CRON",                 // 9
    "LOG_AUTHPRIV",             // 10
    "LOG_FTP",                  // 11
    null,                       // 12
    null,                       // 13
    null,                       // 14
    null,                       // 15
    "LOG_LOCAL0",               // 16
    "LOG_LOCAL1",               // 17
    "LOG_LOCAL2",               // 18
    "LOG_LOCAL3",               // 19
    "LOG_LOCAL4",               // 20,
    "LOG_LOCAL5",               // 21,
    "LOG_LOCAL6",               // 22,
    "LOG_LOCAL7",               // 23
];

var __levelNames = [
    "LOG_EMERG",                // 0
    "LOG_ALERT",                // 1
    "LOG_CRIT",                 // 2
    "LOG_ERR",                  // 3
    "LOG_WARNING",              // 4
    "LOG_NOTICE",               // 5
    "LOG_INFO",                 // 6
    "LOG_DEBUG",                // 7
];

// KernelLogEntry_Post_5_10:
//
// An abstraction of a particular entry in the printK log (at or after the 5.10.x series of Linux
// kernels which completely reworked the printk subsystem).
//
class __KernelLogEntry_Post_5_10
{
    constructor(logInfo, session, idx, descAddr, infoAddr, dataPtr, dataLen)
    {
        this.__logInfo = logInfo;
        this.__session = session;
        this.__idx = idx;
        this.__descAddr = descAddr;
        this.__infoAddr = infoAddr;
        this.__dataPtr = dataPtr;
        this.__dataLen = dataLen;

        var ts_nsec = host.memory.readMemoryValues(
            infoAddr.add(logInfo.printk_info_offsets.ts_nsec),
            1,
            8,
            false,
            session)[0];

        this.__ts_nsec = ts_nsec;

        var ns = ts_nsec.convertToNumber();
        var sec = ns / 1000000000;

        //
        // The data is an atomic ID (of the owner) followed by the actual text.  Get the actual
        // text.
        //
        // @TODO: On 32-bit platforms, the ID here is probably 32-bits and not 64.  We currently only support
        //        64-bit platforms but this should be fixed.
        //
        // @TODO: This is not 100% correct.  The string is UTF8 and we need to be able
        //        to read it as a UTF8 string with the proper conversion to a JS string.
        //        There should be a readString variant which takes the encoding.
        //
        if (dataPtr != null)
        {
            var textPtr = dataPtr.add(8);
            var dataPossibleTextLen = dataLen.subtract(8);

            var textReadLen = host.memory.readMemoryValues(
                infoAddr.add(logInfo.printk_info_offsets.text_len),
                1,
                2,
                false,
                session)[0];

            if (textReadLen > dataPossibleTextLen)
            {
                textReadLen = dataPossibleTextLen;
            }

            var stext = sec.toFixed(6).padStart(13, ' ');
            var logText = host.memory.readString(textPtr, textReadLen);

            this.__logText = logText;
            this.__strConv = "[" + stext + "] " + logText;
        }
        else
        {
            var stext = sec.toFixed(6).padStart(13, ' ');
            this.__logText = null;
            this.__strConv = "[" + stext + "]";
        }
    }

    toString()
    {
        return this.__strConv;
    }

    get Text()
    {
        return this.__logText;
    }

    get TimeStamp()
    {
        return this.__ts_nsec;
    }

    //*************************************************
    // Only available with kernel symbols:
    //

    get Facility()
    {
        if (this.__logInfo.printkInfoType)
        {
            var obj = host.createTypedObject(this.__infoAddr, this.__logInfo.printkInfoType);
            var facilityNum = obj.facility;
            if (facilityNum < __facilityNames.length)
            {
                return __facilityNames[facilityNum];
            }
            return "UNKNOWN";
        }
        return null;
    }

    get Level()
    {
        if (this.__logInfo.printkInfoType)
        {
            var obj = host.createTypedObject(this.__infoAddr, this.__logInfo.printkInfoType);
            var levelNum = obj.level;

            //
            // @TODO: Bitfields are not propagating correctly all the way through to the "dot operator". here for
            //        DWARF symbols.  Until this is fixed, mask off the level by hand.
            //
            levelNum &= 0x7;
    
            if (levelNum < __levelNames.length)
            {
                return __levelNames[levelNum];
            }
            return "UNKNOWN";
        }
        return null;
    }
}

// KernelLogEntry_Pre_5_10:
//
// An abstraction of a particular entry in the printK log (prior to the 5.10.x series of Linux
// kernels which completely reworked the printk subsystem).
//
class __KernelLogEntry_Pre_5_10
{
    constructor(logInfo, session, pkAddr)
    {
        this.__logInfo = logInfo;
        this.__pkAddr = pkAddr;
        this.__session = session;

        var textLen = host.memory.readMemoryValues(pkAddr.add(logInfo.printk_log_text_len_offset),
                                                   1,
                                                   2,
                                                   false,
                                                   this.__session)[0];

        var dictLen = host.memory.readMemoryValues(pkAddr.add(logInfo.printk_log_dict_len_offset),
                                                   1,
                                                   2,
                                                   false,
                                                   this.__session)[0];

        var tsNsec = host.memory.readMemoryValues(pkAddr.add(logInfo.printk_log_ts_nsec_offset),
                                                  1,
                                                  8,
                                                  false,
                                                  this.__session)[0];

        this.__ts_nsec = tsNsec;

        var ns = tsNsec.convertToNumber();
        var sec = ns / 1000000000;

        //
        // @TODO: This is not 100% correct.  The string is UTF8 and we need to be able
        //        to read it as a UTF8 string with the proper conversion to a JS string.
        //        There should be a readString variant which takes the encoding.
        //
        var textAddr = pkAddr.add(this.__logInfo.printk_log_size);
        var dictAddr = textAddr.add(textLen);
        var stext = sec.toFixed(6).padStart(13, ' ');
        var logText = host.memory.readString(textAddr, textLen);

        this.__logText = logText;
        this.__strConv = "[" + stext + "] " + logText;

        var dictText = "";
        this.__dictionary = {};
        
        if (dictLen > 0)
        {
            var remainingLen = dictLen;
            
            //
            // It's a key/value store much like a separated list of environment variables.  Each
            // key/value is separated by a null character in the string.
            //
            while(remainingLen > 0)
            {
                var kvpStr = host.memory.readString(dictAddr, remainingLen);
                var eqIdx = kvpStr.indexOf("=");
                if (eqIdx == -1)
                {
                    break;
                }

                //
                // Find the embedded null character which delimits each property in the dictionary and
                // ensure we only have the first property.
                //
                var nullIdx = kvpStr.indexOf("\0");
                if (nullIdx != -1)
                {
                    kvpStr = kvpStr.substr(0, nullIdx);
                }

                var keyStr = kvpStr.substr(0, eqIdx);
                var valStr = kvpStr.substr(eqIdx + 1);
                this.__dictionary[keyStr] = valStr;

                if (kvpStr.length + 1 > remainingLen)
                {
                    break;
                }

                dictAddr = dictAddr.add(kvpStr.length + 1);
                remainingLen -= kvpStr.length + 1;
            }
        }
    }

    toString()
    {
        return this.__strConv;
    }

    get Text()
    {
        return this.__logText;
    }

    get TimeStamp()
    {
        return this.__ts_nsec;
    }

    get Dictionary()
    {
        return this.__dictionary;
    }

    //*************************************************
    // Only available with kernel symbols:
    //

    get Facility()
    {
        if (this.__logInfo.printkLogType)
        {
            var obj = host.createTypedObject(this.__pkAddr, this.__logInfo.printkLogType);
            var facilityNum = obj.facility;
            if (facilityNum < __facilityNames.length)
            {
                return __facilityNames[facilityNum];
            }
            return "UNKNOWN";
        }
        return null;
    }

    get Level()
    {
        if (this.__logInfo.printkLogType)
        {
            var obj = host.createTypedObject(this.__pkAddr, this.__logInfo.printkLogType);
            var levelNum = obj.level;

            //
            // @TODO: Bitfields are not propagating correctly all the way through to the "dot operator". here for
            //        DWARF symbols.  Until this is fixed, mask off the level by hand.
            //
            levelNum &= 0x7;

            if (levelNum < __levelNames.length)
            {
                return __levelNames[levelNum];
            }
            return "UNKNOWN";
        }
        return null;
    }
}

// KernelLog:
//
// An abstraction over the printk log in the Linux kernel.
//
class __KernelLog
{
    constructor(session)
    {
        this.__session = session;
        this.__initialized = false;
    }

    __init()
    {
        if (!this.__initialized)
        {
            this.__logInfo = __getKernelInfo().printKLogInfo;
        }
        this.__initialized = true;
    }

    *[Symbol.iterator]()
    {
        this.__init();

        var logInfo = this.__logInfo;

        if (logInfo.pre_5_10_kernel)
        {
            var firstIdx = host.memory.readMemoryValues(logInfo.log_first_idx_addr, 
                                                        1, 
                                                        4, 
                                                        false, 
                                                        this.__session)[0];

            var nextIdx = host.memory.readMemoryValues(logInfo.log_next_idx_addr,
                                                       1,
                                                       4,
                                                       false,
                                                       this.__session)[0];

            var logLen = host.memory.readMemoryValues(logInfo.log_buf_len_addr,
                                                      1,
                                                      4,
                                                      false,
                                                      this.__session)[0];

            var logBuf = host.memory.readMemoryValues(logInfo.log_buf_addr,
                                                      1,
                                                      __getKernelInfo().pointerSize,
                                                      false,
                                                      this.__session)[0];

                                            
            var curIdx = firstIdx;
            var cycled = false;
            var bufRemaining = logLen - firstIdx;

            if (nextIdx > firstIdx)
            {
                cycled = true;
                bufRemaining = nextIdx - firstIdx;
            }

            //
            // The PrintK log is a cyclic buffer.  curIdx==nextIdx is either empty or full.
            // Entries are assigned 64-bit sequence numbers.  Empty is both sequence numbers
            // equal.
            //
            // Unfortunately, the sequence numbers aren't saved in VMCOREINFO.  We are going to assume
            // that the log buffer isn't empty if we're here.
            //
            while (bufRemaining > 0)
            {
                if (bufRemaining < logInfo.printk_log_size)
                {
                    if (cycled)
                    {
                        break;
                    }
                    curIdx = 0;
                    cycled = true;
                    bufRemaining = logInfo.nextIdx;
                }

                var entryAddr = logBuf.add(curIdx);
                var len = host.memory.readMemoryValues(entryAddr.add(logInfo.printk_log_len_offset),
                                                       1,
                                                       2,
                                                       false,
                                                       this.__session)[0];
                                                       

                //
                // An empty entry is a marker in the PrintK log that the message would not fit at the
                // end and has instead cycled around to the start of the log.
                //
                if (len == 0)
                {
                    if (cycled)
                    {
                        break;
                    }
                    curIdx = 0;
                    cycled = true;
                    bufRemaining = nextIdx;

                    entryAddr = logBuf;
                    len = host.memory.readMemoryValues(entryAddr.add(logInfo.printk_log_len_offset),
                                                       1,
                                                       2,
                                                       false,
                                                       this.__session)[0];
                }

                yield new __KernelLogEntry_Pre_5_10(logInfo, this.__session, entryAddr);

                bufRemaining = bufRemaining.subtract(len);
                curIdx = curIdx.add(len);
            }
        }
        else
        {
            //
            // Find the size of the descriptor and data rings for this KPRB and the bit masks
            // necessary to find any index from the atomic sequence numbers.
            //
            var prbAddr = host.memory.readMemoryValues(logInfo.prb_addr,
                                                       1,
                                                       __getKernelInfo().pointerSize,
                                                       false,
                                                       this.__session)[0];

            var desc_count_bits = host.memory.readMemoryValues(
                prbAddr.add(logInfo.printk_ringbuffer_offsets.desc_ring).
                        add(logInfo.prb_desc_ring_offsets.count_bits),
                1,
                4,
                false,
                this.__session)[0];

            var data_size_bits = host.memory.readMemoryValues(
                prbAddr.add(logInfo.printk_ringbuffer_offsets.text_data_ring).
                        add(logInfo.prb_data_ring_offsets.size_bits),
                1,
                4,
                false,
                this.__session)[0];


            var desc_size = (1 << desc_count_bits);
            var data_size = (1 << data_size_bits);
            var desc_mask = desc_size - 1;
            var data_mask = data_size - 1;

            //
            // The head and tail sequence numbers are stored in the descriptor ring.
            //
            var tailSeq = host.memory.readMemoryValues(
                prbAddr.add(logInfo.printk_ringbuffer_offsets.desc_ring).
                        add(logInfo.prb_desc_ring_offsets.tail_id),
                1,
                logInfo.atomic_long_t_size,
                false,
                this.__session)[0];
            
            var headSeq = host.memory.readMemoryValues(
                prbAddr.add(logInfo.printk_ringbuffer_offsets.desc_ring).
                        add(logInfo.prb_desc_ring_offsets.head_id),
                1,
                logInfo.atomic_long_t_size,
                false,
                this.__session)[0];

            var curSeq = tailSeq;

            var tailNum = tailSeq.bitwiseAnd(desc_mask);
            var headNum = headSeq.bitwiseAnd(desc_mask);
            var cur = tailNum;

            var descsAddr = host.memory.readMemoryValues(
                prbAddr.add(logInfo.printk_ringbuffer_offsets.desc_ring).
                        add(logInfo.prb_desc_ring_offsets.descs),
                1,
                __getKernelInfo().pointerSize,
                false,
                this.__session)[0];

            var infosAddr = host.memory.readMemoryValues(
                prbAddr.add(logInfo.printk_ringbuffer_offsets.desc_ring).
                        add(logInfo.prb_desc_ring_offsets.infos),
                1,
                __getKernelInfo().pointerSize,
                false,
                this.__session)[0];

            var dataPtr = null;
            var dataLen = 0;
            while (cur != headNum)
            {
                var descAddr = descsAddr.add(logInfo.prb_desc_size * cur);
                var infoAddr = infosAddr.add(logInfo.printk_info_size * cur);

                //
                // Make sure this descriptor is in a valid state.
                //
                var stateVar = host.memory.readMemoryValues(
                    descAddr.add(logInfo.prb_desc_offsets.state_var),
                    1,
                    logInfo.atomic_long_t_size,
                    false,
                    this.__session)[0];


                var id = stateVar.bitwiseAnd(logInfo.idMask);
                var flags = stateVar.bitwiseAnd(logInfo.stateFlagsMask).bitwiseShiftRight(logInfo.stateFlagsShift);

                //
                // If the descriptor doesn't match the sequence number, it's a miss.
                // Further, state==0 is reserved but not committed.  It's in the middle of being written.  Move on.
                //          state==1/2 is committed (1 == reopenable, 2 == finalized)
                //          state==3 is free
                //
                var idValid = (id.compareTo(curSeq) == 0);
                var stateValid = (flags.compareTo(1) == 0 || flags.compareTo(2) == 0);

                if (idValid && stateValid)
                {
                    var textPosAddr = descAddr.add(logInfo.prb_desc_offsets.text_blk_lpos);

                    var begin = host.memory.readMemoryValues(
                        textPosAddr.add(logInfo.prb_data_blk_lpos_offsets.begin),
                        1,
                        8,
                        false,
                        this.__session)[0];

                    var next = host.memory.readMemoryValues(
                        textPosAddr.add(logInfo.prb_data_blk_lpos_offsets.next),
                        1,
                        8,
                        false,
                        this.__session)[0];
                        
                    if (begin.bitwiseAnd(1).compareTo(1) == 0 &&
                        next.bitwiseAnd(1).compareTo(1) == 0)
                    {
                        //
                        // The entry is dataless and has no text associated with it.
                        //
                    }
                    else
                    {
                        begin = begin.bitwiseAnd(data_mask);
                        next = next.bitwiseAnd(data_mask);

                        //
                        // Per the kernel commentary in printk_ringbuffer.c:
                        //
                        //  * If the writer data of a data block would extend beyond the end of the
                        //  * byte array, only the ID of the data block is stored at the logical
                        //  * position and the full data block (ID and writer data) is stored at the
                        //  * beginning of the byte array. The referencing blk_lpos will point to the
                        //  * ID before the wrap and the next data block will be at the logical
                        //  * position adjacent the full data block after the wrap.
                        //
                        if (next < begin && next != 0)
                        {
                            begin = 0;
                        }

                        dataPtr = host.memory.readMemoryValues(
                            prbAddr.add(logInfo.printk_ringbuffer_offsets.text_data_ring).
                                    add(logInfo.prb_data_ring_offsets.data),
                            1,
                            __getKernelInfo().pointerSize,
                            false,
                            this.__session)[0];
                            
                        dataPtr = dataPtr.add(begin);
                        dataLen = next.subtract(begin);
                    }

                    yield new __KernelLogEntry_Post_5_10(logInfo, 
                                                         this.__session,
                                                         cur, descAddr, infoAddr, dataPtr, dataLen);
                }
                
                //
                // Move onto the next potential entry.
                //
                cur = cur.add(1);
                if (cur.compareTo(desc_size) >= 0)
                {
                    cur = new host.Int64(0);
                }

                curSeq = curSeq.add(1);
            }
        }
    }
}

// __KernelInformation:
//
// General Linux kernel information.  Projected as 'Kernel' on the session object.
//
class __KernelInformation
{
    constructor(session)
    {
        this.__session = session;
    }

    //*************************************************
    // Properties:
    //

    get PrintKLog()
    {
        return new __KernelLog(this.__session);
    }

    get BlockDevices()
    {
        var blockDevicesList = __getKernelInfo().deviceInfo.blockDevicesList;
        return new __ListTraversal(blockDevicesList, "block_device", "bd_list");
    }

    get CharacterDevices()
    {
        return new __CharacterDevices();
    }

    get FileSystems()
    {
        var superBlocks = __getKernelInfo().fileSystemInfo.superBlockList;
        return new __ListTraversal(superBlocks, "super_block", "s_list");
    }

    get NetworkNamespaces()
    {
        var networkNamespaces = __getKernelInfo().namespaceInfo.netNamespaceList;
        return new __ListTraversal(networkNamespaces, "net", "list");
    }

    get KernFSRoot()
    {
        return __getKernelInfo().kernFsInfo.root;
    }

    get Timers()
    {
        var hrtimerBases = this.GetAllPerCpuInstances(__getKernelInfo().timerInfo.hrtimerBases).value;
        var newTimers = new __NewTimerList(hrtimerBases);

        var timerBases = this.GetAllPerCpuInstances(__getKernelInfo().timerInfo.timerBases).value;
        var oldTimers = new __OldTimerList(timerBases);

        var timers = { OldTimers: oldTimers, NewTimers: newTimers };

        //
        // Metadata for the property must be in the descriptor: PreferredExpansionDepth: 4...
        //
        return timers;
    }

    //*************************************************
    // Methods:
    //

    GetPerCpuInstance(argVar, cpuNum)
    {
        return __getPerCpuInstance(argVar, cpuNum);
    }

    GetAllPerCpuInstances(argVar)
    {
        var perCpuInfo = __getKernelInfo().perCpuInfo;
        var argVarAddr = argVar.address;
        var argVarType = argVar.targetType;

        if (argVarAddr.compareTo(perCpuInfo.perCpuStart) < 0 || argVarAddr.compareTo(perCpuInfo.perCpuEnd) > 0)
        {
            throw new Error("Argument is not a per-cpu variable within the Linux kernel");
        }

        var collection = new __perCpuCollection(argVarAddr, argVarType);
        return new host.metadata.valueWithMetadata(collection, {PreferredExpansionDepth: 2});
    }

    //*************************************************
    // Metadata:
    //

    get [Symbol.metadataDescriptor]()
    {
        return { GetPerCpuInstance: {Help: "GetPerCpuInstance(argVar, [cpuNum]) - Gets a given instance of a per-cpu kernel variable.  If the cpu number is not specified, the current CPU is used"},
                 GetAllPerCpuInstances: {Help: "GetAllPerCpuInstance(argVar) - Gets a collection of every instance of a per-cpu kernel variable" },
                 Timers: {PreferredExpansionDepth: 4} };
    }
}

// __getPerCpuInstance:
//
// Gets a per-cpu instance of a variable for a given cpu.
//
function __getPerCpuInstance(argVar, cpuNum)
{
    var perCpuInfo = __getKernelInfo().perCpuInfo;
    var argVarAddr = argVar.address;
    var argVarType = argVar.targetType;

    if (argVarAddr.compareTo(perCpuInfo.perCpuStart) < 0 || argVarAddr.compareTo(perCpuInfo.perCpuEnd) > 0)
    {
        throw new Error("Argument is not a per-cpu variable within the Linux kernel");
    }

    if (cpuNum === undefined)
    {
        cpuNum = host.currentProcess.KernelObject.cpu;
    }

    if (cpuNum >= perCpuInfo.perCpuOffsetSize)
    {
        throw new RangeError("Unrecognized CPU number");
    }

    var perCpuOffset = perCpuInfo.perCpuOffset[cpuNum];
    if (perCpuOffset.compareTo(0) == 0)
    {
        throw new RangeError("Unrecognized CPU number");
    }

    var perCpuInstance = host.createTypedObject(argVarAddr.add(perCpuOffset), argVarType);
    return perCpuInstance;
}

// __perCpuCollection:
//
// Helper class to return a collection of every instance of a per-cpu variable in the Linux kernel.
//
class __perCpuCollection
{
    constructor(argVarAddr, argVarType)
    {
        this.__argVarAddr = argVarAddr;
        this.__argVarType = argVarType;
    }

    *[Symbol.iterator]()
    {
        var perCpuInfo = __getKernelInfo().perCpuInfo;
        var cpuNum = 0;
        while (cpuNum < perCpuInfo.perCpuOffsetSize)
        {
            var perCpuOffset = perCpuInfo.perCpuOffset[cpuNum];
            if (perCpuOffset.compareTo(0) != 0)
            {
                var perCpuInstance = host.createTypedObject(this.__argVarAddr.add(perCpuOffset), this.__argVarType);
                yield new host.indexedValue(perCpuInstance, [cpuNum]);
            }
            ++cpuNum;
        }
    }

    getDimensionality()
    {
        return 1;
    }

    getValueAt(idx)
    {
        var perCpuInfo = __getKernelInfo().perCpuInfo;
        var perCpuOffset = perCpuInfo.perCpuOffset[idx];
        if (perCpuOffset.compareTo(0) == 0)
        {
            throw new RangeError("Unrecognized CPU number");
        }

        var perCpuInstance = host.createTypedObject(this.__argVarAddr.add(perCpuOffset), this.__argVarType);
        return perCpuInstance;
    }
}



//**************************************************************************
// Visualizers:
//

//*************************************************
// KernFS / SysFS:
//

class __KernFsNodeVisualizer
{
    toString()
    {
        var name = host.memory.readString(this.name);
        var parent = this.parent;
        if (parent.isNull)
        {
            return name;
        }
        else
        {
            return this.parent.dereference().toString() + "/" + name;
        }
    }

    //
    // This is only the right "private data" for a bus. 
    //
    get SubSysPrivate()
    {
        if (this.__isBus())
        {
            var privKObjVoid = this.priv;

            var kernFsInfo = __getKernelInfo().kernFsInfo;
            var addr = privKObjVoid.address.subtract(kernFsInfo.subSysOffset + kernFsInfo.kobjOffset);
            return host.createTypedObject(addr, kernFsInfo.subSysPrivateType);
        }
    }

    get Children()
    {
        var rbNodePtr = this.dir.children.rb_node;
        if (rbNodePtr.isNull)
        {
            return [];
        }

        return new __RbTraversal(rbNodePtr.dereference(), "kernfs_node", "rb");
    }

    // __isBus():
    //
    // Makes a determination of whether this node is a bus and subsqeuently its data is
    // a subsys_private.
    //
    __isBus()
    {
        return (this.__getType() == "bus");
    }

    // __isClass():
    //
    // Make a determination of whether this node is a class and subsequently its data is
    // a <@TODO>.
    //
    __isClass()
    {
        return (this.__getType() == "class");
    }

    // __getType():
    //
    // Returns the type of node.
    //
    __getType()
    {
        //
        // @TODO: There should really be a better way to do this!
        //
        var l1 = this;
        var parent = l1.parent;
        while(!parent.isNull && !l1.isNull)
        {
            var upl = parent.parent;
            if (upl.isNull)
            {
                break;
            }
            l1 = parent;
            parent = l1.parent;
        }
        return host.memory.readString(l1.name);
    }
}

//*************************************************
// Devices:
//

// __DevicePrivateVisualizer:
//
// Visualizer on the kernel "device_private" type.
//
class __DevicePrivateVisualizer
{
    toString()
    {
        // Return the full string from the kernfs path:
        var kernFsPath = this.device.kobj.sd.dereference().toString();
        var driver = this.device.driver;
        if (!driver.isNull)
        {
            var driverName = host.memory.readString(this.device.driver.name);
            return kernFsPath + " (by " + driverName + ")";
        }
        else
        {
            return kernFsPath;
        }
    }
}

// __SubSysPrivateDevices:
//
class __SubSysPrivateDevices
{
    constructor(subSysPrivate)
    {
        this.__subSysPrivate = subSysPrivate;
    }

    *[Symbol.iterator]()
    {
        var klist = this.__subSysPrivate.klist_devices;
        yield* new __KListTraversal(klist, "device_private", "knode_bus");
    }
}

// __SubSysPrivateVisualizer:
//
// Visualizer on the kernel "subsys_private" type.
//
class __SubSysPrivateVisualizer
{
    get Devices()
    {
        return new __SubSysPrivateDevices(this);
    }
}

// __CharacterDevices:
//
// Enumerator for the hash of character devices.
//
class __CharacterDevices
{
    *[Symbol.iterator]()
    {
        var deviceInfo = __getKernelInfo().deviceInfo;
        var characterDevices = deviceInfo.characterDevicesList;
        var count = deviceInfo.characterDevicesCount;

        for (var index = 0; index < count; ++index)
        {
            var devPtr = characterDevices.getValueAt(index);
            if (!devPtr.isNull)
            {
                yield devPtr.dereference();
            }
        }
    }
}

// __CharDeviceStructVisualizer:
//
// Visualizer on the kernel "char_device_struct" type.
//
class __CharDeviceStructVisualizer
{
    toString()
    {
        var name = this.major.toString(10) + " = " + host.memory.readString(this.name);
        return name;
    }
}

// __BlockDeviceVisualizer:
//
// Visualizer on the kernel "block_device" type.
//
class __BlockDeviceVisualizer
{
    toString()
    {
        var deviceInfo = __getKernelInfo().deviceInfo;
        var majorNames = deviceInfo.majorNames;
        var majorNamesCount = deviceInfo.majorNamesCount;
        var majorNumber = this.bd_dev >> 20;
        var index = majorNumber % majorNamesCount;

        var nameInfo = majorNames.getValueAt(index);
        while(index < majorNamesCount)
        {
            if (nameInfo.isNull)
            {
                return majorNumber.toString(10) + " = <unknown>";
            }
            else if (nameInfo.major == majorNumber)
            {
                return majorNumber.toString(10) + " = " + host.memory.readString(nameInfo.name);
            }

            nameInfo = nameInfo.add(1);
            ++index;
        }
    }
}

// __Devices:
//
// Proxy for !dev to combine block & character.
//
class __Devices
{
    get BlockDevices()
    {
        return host.currentSession.Kernel.BlockDevices;
    }

    get CharacterDevices()
    {
        return host.currentSession.Kernel.CharacterDevices;
    }
}

//*************************************************
// Network:
//

// __InIfAddrVisualizer:
//
// Visualizer on the kernel "in_ifaddr" type.
//
class __InIfAddrVisualizer
{
    toString()
    {
        var ip32 = this.ifa_address;
        var str = "";
        str += (ip32 & 0xFF).toString() + "." +
               ((ip32 >> 8) & 0xFF).toString() + "." +
               ((ip32 >> 16) & 0xFF).toString() + "." +
               ((ip32 >> 24) & 0xFF);

        return str;
    }
}

// __NetDeviceIPv4AddressList
//
// Enumerates all IPv4 addresses on a net_device
//
class __NetDeviceIPv4AddressList
{
    constructor(netDevice)
    {
        this.__netDevice = netDevice;
    }

    *[Symbol.iterator]()
    {
        var in_device = this.__netDevice.ip_ptr.dereference();
        var ifa = in_device.ifa_list;
        while(!ifa.isNull)
        {
            yield ifa.dereference();
            ifa = ifa.ifa_next;
        }
    }
}

// __NetDeviceVisualizer:
//
// Visualizer on the kernel "net_device" type.
//
class __NetDeviceVisualizer
{
    toString()
    {
        // @TODO: UTF8:
        var devName = host.memory.readString(this.name.address, this);

        var ipv4 = null;
        for (var in_ifaddr of this.IPv4Addresses)
        {
            ipv4 = in_ifaddr.toString();
            break;
        }

        if (ipv4)
        {
            return devName + " (" + ipv4 + ")";
        }
        
        return devName;
    }

    get IPv4Addresses()
    {
        return new __NetDeviceIPv4AddressList(this);
    }
}

// __NetVisualizer:
//
// Visualizer on the kernel "net" type.
//
class __NetVisualizer
{
    get Devices()
    {
        return new __ListTraversal(this.dev_base_head, "net_device", "dev_list"); 
    }
}

//*************************************************
// File System:
//

// __DEntryVisualizer:
//
// Visualizer on the kernel "dentry" type.
//
class __DEntryVisualizer
{
    toString()
    {
        // @TODO: UTF8...
        var localName = host.memory.readString(this.d_name.name.address, this);
        var parent = this.d_parent.dereference();
        if (this.address.compareTo(parent.address) != 0)
        {
            return __pathCombine(parent.toString(), localName);
        }
        else
        {
            return localName;
        }
    }
}

// __PathVisualizer:
//
// Visualizer on the kernel "path" type.
//
class __PathVisualizer
{
    toString()
    {
        var mountPath = this.Mount.Path;
        return __pathCombine(mountPath, this.dentry.dereference().toString());
    }

    get Mount()
    {
        var mountTy = host.getModuleType("vmlinux", "mount");
        var mntFld = mountTy.fields.mnt;
        var mntOffset = mntFld.offset;
        return host.createTypedObject(this.mnt.address.subtract(mntOffset), mountTy);
    }
}

// __FileVisualizer:
//
// Visualizer on the kernel "file" type.
//
class __FileVisualizer
{
    toString()
    {
        return this.f_path.toString();
    }
}

// __MntNamespaceVisualizer:
//
// Visualizer on the kernel "mnt_namespace" type.
//
class __MntNamespaceVisualizer
{
    get Mounts()
    {
        return new __ListTraversal(this.list, "mount", "mnt_list");
    }
}

// __MountVisualizer:
//
// Visualizer on the kernel "mount" type.
//
class __MountVisualizer
{
    toString()
    {
        var mountPoint = this.mnt_mountpoint.dereference().toString();
        var superBlock = this.mnt.mnt_sb;
        
        // @TODO: UTF8
        var sbTypeName = host.memory.readString(superBlock.s_type.name.address, superBlock);

        // @TODO: UTF8
        var deviceName = host.memory.readString(this.mnt_devname.address, this);
        return "(" + sbTypeName + ") " + deviceName + " at " + mountPoint;
    }

    get Path()
    {
        return this.mnt_mountpoint.dereference().toString();
    }
}

// __SuperBlockVisualizer:
//
// Visualizer on the kernel "super_block" type.
//
class __SuperBlockVisualizer
{
    toString()
    {
        // @TODO: UTF8
        var sbTypeName = host.memory.readString(this.s_type.name.address, this);
        return sbTypeName;
    }

    get Mounts()
    {
        return new __ListTraversal(this.s_mounts, "mount", "mnt_instance");
    }
}

// __QStrVisualizer:
//
// Visualizer on the kernel "qstr" type.
//
class __QStrVisualizer
{
    toString()
    {
        return host.memory.readString(this.name.address, this.len);
    }
}

// __KernelProcessFiles:
//
// List of files within a process.  Attempts to mirror 'files' functionality of the Linux
// crash tool.
//
class __KernelProcessFiles
{
    constructor(task)
    {
        this.__task = task;
    }

    toString()
    {
        // @TODO: UTF8
        var taskName = host.memory.readString(this.__task.comm.address, this.__task);
        var str = "Files for process '" + taskName + "' (pid " + this.__task.pid.toString() + ")";
        var fsRoot = this.__task.fs.root.toString();
        var wdir = this.__task.fs.pwd.toString();
        str += " root dir = '" + fsRoot + "' working dir = '" + wdir + "'";
        return str;
    }

    getDimensionality()
    {
        return 1;
    }

    getValueAt(idx)
    {
        var files = this.__task.files.dereference();
        var fdt = files.fdt.dereference();
        var ct = fdt.max_fds;
        var ppfd = fdt.fd;
        if (idx >= ct)
        {
            throw new RangeError("Invalid file descriptor");
        }
        if (idx > 0)
        {
            ppfd = ppfd.add(idx);
        }
        var pfd = ppfd.dereference();
        if (pfd.isNull)
        {
            throw new RangeError("Invalid file descriptor");
        }
        return pfd.dereference();
    }

    *[Symbol.iterator]()
    {
        var files = this.__task.files.dereference();
        var fdt = files.fdt.dereference();
        var ct = fdt.max_fds;
        var ppfd = fdt.fd;
        for(var i = 0; i < ct; ++i)
        {
            var pfd = ppfd.dereference();
            if (!pfd.isNull)
            {
                yield new host.indexedValue(pfd.dereference(), [i]);
            }

            ppfd = ppfd.add(1);
        }
    }
}

//*************************************************
// Memory:
//

var __vmFlags =
[
    "VM_READ",              // 0x00000001
    "VM_WRITE",             // 0x00000002
    "VM_EXEC",              // 0x00000004
    "VM_SHARED",            // 0x00000008
    "VM_MAYREAD",           // 0x00000010
    "VM_MAYWRITE",          // 0x00000020
    "VM_MAYEXEC",           // 0x00000040
    "VM_MAYSHARE",          // 0x00000080
    "VM_GROWSDOWN",         // 0x00000100
    "VM_UFFD_MISSING",      // 0x00000200
    "VM_PFNMAP",            // 0x00000400
    "VM_DENYWRITE",         // 0x00000800
    "VM_UFFD_WP",           // 0x00001000
    "VM_LOCKED",            // 0x00002000
    "VM_IO",                // 0x00004000
    "VM_SEQ_READ",          // 0x00008000
    "VM_RAND_READ",         // 0x00010000
    "VM_DONTCOPY",          // 0x00020000
    "VM_DONTEXPAND",        // 0x00040000
    "VM_LOCKONFAULT",       // 0x00080000
    "VM_ACCOUNT",           // 0x00100000
    "VM_NORESERVE",         // 0x00200000
    "VM_HUGETLB",           // 0x00400000
    "VM_SYNC",              // 0x00800000
    "VM_ARCH_1",            // 0x01000000
    "VM_WIPEONFORK",        // 0x02000000
    "VM_DONTDUMP",          // 0x04000000
    "VM_SOFTDIRTY",         // 0x08000000
    "VM_MIXEDMAP",          // 0x10000000
    "VM_HUGEPAGE",          // 0x20000000
    "VM_NOHUGEPAGE",        // 0x40000000
    "VM_MERGEABLE"          // 0x80000000
];

// __VmAreaStructVisualizer:
//
// Visualizer on the "vm_area_struct" type.
//
class __VmAreaStructVisualizer
{
    toString()
    {
        var desc = "[" + this.vm_start.toString(16) + " - " + this.vm_end.toString(16) + ")";
        if (!this.vm_file.isNull)
        {
            desc += " = " + this.vm_file.dereference().toString();
        }
        return desc;
    }

    get Flags()
    {
        var flagsVal = { };
        var fdesc = "";
        var hasBit = false;

        var bitVal = new host.Int64(1);
        var flags = this.vm_flags;
        for (var i = 0; i < __vmFlags.length; ++i)
        {
            if (flags.bitwiseAnd(bitVal).compareTo(0) != 0)
            {
                flagsVal[__vmFlags[i]] = true;
                if (hasBit)
                {
                    fdesc += " | ";
                }
                fdesc += __vmFlags[i];
                hasBit = true;
            }
            else
            {
                flagsVal[__vmFlags[i]] = false;
            }
            bitVal = bitVal.bitwiseShiftLeft(1);
        }
        flagsVal.toString = function() { return fdesc; };
        return flagsVal;
    }
}

// __VMAreaList:
//
// Presents as a list of vm_area_structs by walking the va_next links
//
class __VmAreaList
{
    constructor(startVaPtr)
    {
        this.__startVaPtr = startVaPtr;
    }

    *[Symbol.iterator]()
    {
        var ptr = this.__startVaPtr;
        while(!ptr.isNull)
        {
            var vaStruct = ptr.dereference();
            yield vaStruct;
            ptr = vaStruct.vm_next;
        }
    }
}

//*************************************************
// Timers:
//

// __CpuOldTimerList:
//
// Presents the timer_base[] for a CPU as a collection of timer_base structures.
//
class __CpuOldTimerList
{
    constructor(timerBaseArray, cpuNum)
    {
        this.__timerBaseArray = timerBaseArray;
        this.__cpuNum = cpuNum;
    }

    toString()
    {
        return "CPU " + this.__cpuNum.toString();
    }

    *[Symbol.iterator]()
    {
        var id = 0;
        for (var timerBase of this.__timerBaseArray)
        {
            yield new __TimerBaseProjectLists(timerBase, id);
            ++id;
        }
    }
}

// __TimerBaseProjectLists:
//
// Just a projection of .TimerLists on a timer_base.
//
class __TimerBaseProjectLists
{
    constructor(timerBase, id)
    {
        this.__timerBase = timerBase;
        this.__id = id;
    }

    toString()
    {
        if (this.__id == 0)
        {
            return "BASE_STD";
        }
        else if (this.__id == 1)
        {
            return "BASE_DEF";
        }
    }

    *[Symbol.iterator]()
    {
        yield* this.__timerBase.TimerLists;
    }
}

//
// __TimerBaseTimerList
//
// Helper for filtering out relevant timer lists from a timer base (the list items)
//
class __TimerBaseTimerList
{
    constructor(timerBase, hentry)
    {
        this.__timerBase = timerBase;
        this.__hentry = hentry;
    }

    *[Symbol.iterator]()
    {
        var timerInfo = __getKernelInfo().timerInfo;
        var hentry = this.__hentry;

        while (!hentry.isNull)
        {
            var timerList = host.createTypedObject(hentry.address.subtract(timerInfo.entryOffset), 
                                                   timerInfo.timerListType);
            yield timerList;

            hentry = hentry.next;
        }
    }
}

// __TimerBaseTimerLists
//
// Helper for filtering out relevant timer lists from a timer base (the hash buckets)
//
class __TimerBaseTimerLists
{
    constructor(timerBase)
    {
        this.__timerBase = timerBase;
    }

    *[Symbol.iterator]()
    {
        //
        // There's a series of hash buckets in vec which each contain lists of timer_list structures.
        //
        var timerInfo = __getKernelInfo().timerInfo;
        for (var vec of this.__timerBase.vectors)
        {
            var first = vec.first;
            if (!first.isNull)
            {
                yield* new __TimerBaseTimerList(this.__timerBase, first);
            }
        }
    }
}

// __TimerBaseVisualizer:
//
// Visualizer on the kernel timer_base type.
//
class __TimerBaseVisualizer
{
    get TimerLists()
    {
        return new __TimerBaseTimerLists(this);
    }
}

// __TimerListVisualizer:
//
// Visualizer on the kernel timer_list type.
//
class __TimerListVisualizer
{
    toString()
    {
        var expiry = this.expires;
        var func = this.function.dereference();
        var funcName = func.name;
        var tte = this.TimeUntilExpiration;
        return "Expiration = " + expiry + " (TTE = " + tte.toString(10) + ") , Function = " + func.address.toString(16) + " <" + funcName + ">";
    }

    get TimeUntilExpiration()
    {
        return this.expires.subtract(__getKernelInfo().timerInfo.jiffies);
    }
}

// __OldTimerList:
//
// Presents a list of timers from a collection of all per-cpu timer_base structures.
//
class __OldTimerList
{
    constructor(timerBasesArrays)
    {
        this.__timerBasesArrays = timerBasesArrays;
    }

    *[Symbol.iterator]()
    {
        var cpu = 0;
        for (var timerBaseArray of this.__timerBasesArrays)
        {
            yield new __CpuOldTimerList(timerBaseArray.value, cpu);
            ++cpu;
        }
    }
}

// __HrTimerVisualizer:
//
// Visualizer on the kernel hrtimer type.
//
class __HrTimerVisualizer
{
    toString()
    {
        var softExpiry = this._softexpires;
        var func = this.function.dereference();
        var funcName = func.name;
        return "Soft Expiration = " + softExpiry + ", Function = " + func.address.toString(16) + " <" + funcName + ">";
    }
}

// __HrTimerList:
//
// Presents as a list of hrtimers from a clock base by an RB traversal and cast.
//
class __HrTimerList
{
    constructor(clockBase)
    {
        this.__clockBase = clockBase;
    }

    *[Symbol.iterator]()
    {
        var timerInfo = __getKernelInfo().timerInfo;
        var rbNode = this.__clockBase.active.head.rb_node;
        if (!rbNode.isNull)
        {
            var nodeAddr = rbNode.address;
            yield host.createTypedObject(nodeAddr.subtract(timerInfo.nodeOffset), timerInfo.hrtimerType);
            
            var nodes = new __RbTraversal(rbNode, "timerqueue_node", "node");
            for (var node of nodes)
            {
                nodeAddr = node.address;
                yield host.createTypedObject(nodeAddr.subtract(timerInfo.nodeOffset), timerInfo.hrtimerType);
            }
        }
    }
}

// __HrTimerClockBaseVisualizer:
//
// Visualizer for the kernel hrtimer_clock_base structure
//
class __HrTimerClockBaseVisualizer
{
    toString()
    {
        var func = this.get_time.dereference();
        var funcName = func.name;
        return "[" + funcName + "]";
    }

    get Timers()
    {
        return new __HrTimerList(this);
    }
}

class __ClockBaseTimers
{
    constructor(clockBase, num)
    {
        this.__clockBase = clockBase;
        this.__num = num;
    }

    toString()
    {
        return "CLOCK " + this.__num.toString() + " " + this.__clockBase.toString();
    }

    *[Symbol.iterator]()
    {
        for(var timer of this.__clockBase.Timers)
        {
            yield timer;
        }
    }
}

// __CpuTimerList:
//
// Presents an hrtimer_clock_base as a list of clock bases / timers.
//
class __CpuTimerList
{
    constructor(cpuBase, cpuNum)
    {
        this.__cpuBase = cpuBase;
        this.__cpuNum = cpuNum;
    }

    toString()
    {
        return "CPU " + this.__cpuNum.toString();
    }

    *[Symbol.iterator]()
    {
        var clockNum = 0;
        for (var clockBase of this.__cpuBase.clock_base)
        {
            yield new __ClockBaseTimers(clockBase, clockNum);
            ++clockNum;
        }
    }
}

// __NewTimerList:
//
// Presents a list of timers/clock bases from a collection of all per-cpu hrtimer_cpu_base structures.
//
class __NewTimerList
{
    constructor(cpuBases)
    {
        this.__cpuBases = cpuBases;
    }

    *[Symbol.iterator]()
    {
        var cpu = 0;
        for (var cpuBase of this.__cpuBases)
        {
            yield new __CpuTimerList(cpuBase.value, cpu);
            ++cpu;
        }
    }
}

//*************************************************
// __ProcessMemoryExtension:
//
// Extensions placed on a per-process basis
//

class __ProcessMemoryExtension
{
    get VirtualMemoryAreas()
    {
        return new __VmAreaList(this.KernelObject.mm.mmap);
    }
}

//*************************************************
// __ProcessIoExtension:
//
// Extensions placed on a per-process basis
//

class __ProcessIoExtension
{
    get [Symbol.metadataDescriptor]()
    {
        return { Files: { Help: "The list of open files in the process context" } };
    }

    get RootDirectory()
    {
        return this.KernelObject.fs.root;
    }

    get WorkingDirectory()
    {
        return this.KernelObject.fs.pwd;
    }

    get Files()
    {
        return new __KernelProcessFiles(this.KernelObject);
    }

    get MountNamespace()
    {
        return this.KernelObject.nsproxy.mnt_ns.dereference();
    }

    get NetworkNamespace()
    {
        return this.KernelObject.nsproxy.net_ns.dereference();
    }
}

//*************************************************
// __SessionExtension:
//
// Extensions placed on a per-session basis
//

class __SessionExtension
{
    get Kernel()
    {
        return new __KernelInformation(this);
    }
}

//**************************************************************************
// Commands:
//
// These are designed to *somewhat* mirror the commands that present from a Linux crash session.
// Given the architecture is different here, they do not take the same arguments and the like, but their
// *bare* function and simple argument function is similar.
//

// __getTaskFromCommandArgument:
//
// Attempts to get the task_struct associated with a given command argument.   The command argument can
// be in one of several forms:
//
// pid               - Gets the task for the given pid
// 64-bit num        - Gets the task for the task_struct at the given address
// <task struct [*]> - Gets the task_struct for the given object
// <process object>  - Gets the task_struct for the given process
//
// If such cannot be found, null is returned.
//
function __getTaskFromCommandArgument(arg)
{
    var addr = 0;
    if (typeof(arg) == 'number')
    {
        try
        {
            var proc = host.currentSession.Processes.getValueAt(arg);
            return proc.KernelObject;
        }
        catch(exc)
        {
        }

        //
        // It could be an address that wasn't assumed/converted to 64-bit.
        //
        if (arg >= 0x10000)
        {
            var taskStruct = host.createTypedObject(arg, "vmlinux", "task_struct");
            return taskStruct;
        }
    }

    if (arg.asNumber !== undefined)
    {
        //
        // It's not a task_struct pointer with a very low address that looks more like a 
        // PID.
        //
        if (arg.compareTo(0x10000) >= 0)
        {
            var taskStruct = host.createTypedObject(arg, "vmlinux", "task_struct");
            return new __KernelProcessFiles(taskStruct);
        }
    }
    else if (arg.targetType !== undefined)
    {
        var ty = arg.targetType;
        if (ty.typeKind == "pointer")
        {
            arg = arg.dereference();
            ty = arg.targetType;
        }

        if (ty.name == "task_struct")
        {
            return arg;
        }
    }
    else if (arg.KernelObject !== undefined)
    {
        var potentialTask = arg.KernelObject;
        var ty = potentialTask.targetType;
        if (ty.name == "task_struct")
        {
            return potentialTask;
        }
    }

    return null;
}

// __files:
//
// Present as a legacy !files command similar to the crash files command:
//
// !files [<arg>]
//
//     Without [<arg>]             - Equivalent to 'files' -- gives current process file list
//     [<arg>] - pid               - Gives the file list for the given process id
//             - 64-bit num        - Gives the file list for the task at the given address
//             - <task struct [*]> - Gives the file list for the given task struct by object
//             - <process object>  - Gives the file list for the task represented by the process object
//
function __files(arg)
{
    if (arg === undefined)
    {
        return host.currentProcess.Io.Files;
    }

    var taskStruct = __getTaskFromCommandArgument(arg);
    if (taskStruct)
    {
        return new __KernelProcessFiles(taskStruct);
    }

    throw new Error("Illegal argument to files function");
}

// __net:
//
// Present as a legacy !net command similar to the crash net command:
//
// !net [<arg>]
//
//     Without [<arg>]             - Equivalent to 'net' -- gives system network list
//     [<arg>] - pid               - Gives the net list for namespace of the process with the given pid
//             - 64-bit num        - Gives the net list for the namespace of the task_struct given by address
//             - <task struct [*]> - Gives the net list for the namespace of the given task_struct
//             - <process object>  - Gives the net list for the namespace of the task represented by the process object
//
function __net(arg)
{
    if (arg === undefined)
    {
        //
        // PID == 0 is the swapper (system process).  Find its network namespace and dump the device list.
        //
        return host.currentSession.Processes.getValueAt(0).Io.NetworkNamespace.Devices;
    }

    var taskStruct = __getTaskFromCommandArgument(arg);
    if (taskStruct)
    {
        return taskStruct.nsproxy.net_ns.Devices;
    }

    throw new Error("Illegal argument to net function");
}

// __mount:
//
// Present as a legacy !mount command similar to the crash mount command:
//
// !mount [<arg>]
//
//     Without [<arg>]             - Equivalent to 'net' -- gives system network list
//     [<arg>] - pid               - Gives the net list for namespace of the process with the given pid
//             - 64-bit num        - Gives the net list for the namespace of the task_struct given by address
//             - <task struct [*]> - Gives the net list for the namespace of the given task_struct
//             - <process object>  - Gives the net list for the namespace of the task represented by the process object
//
function __mount(arg)
{
    if (arg === undefined)
    {
        //
        // PID == 0 is the swapper (system process).  Find its network namespace and dump the device list.
        //
        return host.currentSession.Processes.getValueAt(0).Io.MountNamespace.Mounts;
    }

    var taskStruct = __getTaskFromCommandArgument(arg);
    if (taskStruct)
    {
        return taskStruct.nsproxy.mnt_ns.Mounts;
    }

    throw new Error("Illegal argument to mount function");
}

// __vm:
//
// Present as a legacy !vm command similar to the crash vm command:
//
// !vm [<arg>]
//
//     Without [<arg>]             - Equivalent to 'vm' -- gives the vm layout for the current process
//
function __vm(arg)
{
    if (arg === undefined)
    {
        return host.currentProcess.Memory.VirtualMemoryAreas;
    }

    var taskStruct = __getTaskFromCommandArgument(arg);
    if (taskStruct)
    {
        return new __VmAreaList(taskStruct.mm.mmap);
    }

    throw new Error("Illegal argument to vm function");
}

// __log:
//
// Present as a legacy !log command similar to the crash log command:
//
// !log
//
function __log()
{
    return host.currentSession.Kernel.PrintKLog;
}

// __dev:
//
// Present as a legacy !dev command similar to the crash dev command:
//
// !dev
//
function __dev()
{
    return new host.metadata.valueWithMetadata(new __Devices(), {PreferredExpansionDepth: 2});
}

// __percpu:
//
// Present as a legacy !percpu command to display per-cpu variables:
//
// !percpu var, [cpu]
//
function __percpu(argVar, cpuNum)
{
    return __getPerCpuInstance(argVar, cpuNum);
}

// __allpercpu:
//
// Present as a legacy !allpercpu command to return a collection of every instance of a per-cpu variable:
//
function __allpercpu(argVar)
{
    var perCpuInfo = __getKernelInfo().perCpuInfo;
    var argVarAddr = argVar.address;
    var argVarType = argVar.targetType;

    if (argVarAddr.compareTo(perCpuInfo.perCpuStart) < 0 || argVarAddr.compareTo(perCpuInfo.perCpuEnd) > 0)
    {
        throw new Error("Argument is not a per-cpu variable within the Linux kernel");
    }

    var collection = new __perCpuCollection(argVarAddr, argVarType);
    return new host.metadata.valueWithMetadata(collection, {PreferredExpansionDepth: 2});
}

// __timer:
//
// Present a legacy !timer command similar to the crash timer command.
//
function __timer()
{
    return new host.metadata.valueWithMetadata(host.currentSession.Kernel.Timers, { PreferredExpansionDepth: 4} );
}

//**************************************************************************
// Script Initialization:
//

// initializeScript:
//
// Initializes our script.  Registers our extensions and various crash like "commands".
//
function initializeScript()
{
    return [new host.apiVersionSupport(1, 5),
            
            //*************************************************
            // Extension Records:
            //
            new host.namedModelParent(__SessionExtension, "Debugger.Models.Session"),
            new host.namespacePropertyParent(__ProcessIoExtension, "Debugger.Models.Process", "Debugger.Models.Process.Io", "Io"),
            new host.namespacePropertyParent(__ProcessMemoryExtension, "Debugger.Models.Process", "Debugger.Models.Process.Memory", "Memory"),

            //*************************************************
            // Visualizer Records (File System):
            //
            new host.typeSignatureExtension(__FileVisualizer, "file", "vmlinux"),
            new host.typeSignatureExtension(__PathVisualizer, "path", "vmlinux"),
            new host.typeSignatureExtension(__DEntryVisualizer, "dentry", "vmlinux"),
            new host.typeSignatureExtension(__SuperBlockVisualizer, "super_block", "vmlinux"),
            new host.typeSignatureExtension(__MountVisualizer, "mount", "vmlinux"),
            new host.typeSignatureExtension(__MntNamespaceVisualizer, "mnt_namespace"),
            new host.typeSignatureRegistration(__QStrVisualizer, "qstr", "vmlinux"),

            //*************************************************
            // Visualizer Records (Network:)
            //
            new host.typeSignatureExtension(__NetVisualizer, "net", "vmlinux"),
            new host.typeSignatureExtension(__NetDeviceVisualizer, "net_device", "vmlinux"),
            new host.typeSignatureExtension(__InIfAddrVisualizer, "in_ifaddr", "vmlinux"),

            //*************************************************
            // Visualizer Records (Memory:)
            //
            new host.typeSignatureExtension(__VmAreaStructVisualizer, "vm_area_struct", "vmlinux"),

            //*************************************************
            // Visualizer Records (Devices:)
            //
            new host.typeSignatureExtension(__BlockDeviceVisualizer, "block_device", "vmlinux"),
            new host.typeSignatureExtension(__CharDeviceStructVisualizer, "char_device_struct", "vmlinux"),
            new host.typeSignatureExtension(__DevicePrivateVisualizer, "device_private", "vmlinux"),

            //*************************************************
            // Visualizer Records (KernFS):
            //
            new host.typeSignatureExtension(__KernFsNodeVisualizer, "kernfs_node", "vmlinux"),
            new host.typeSignatureExtension(__SubSysPrivateVisualizer, "subsys_private", "vmlinux"),

            //*************************************************
            // Visualizer Records (Timers:)
            //
            new host.typeSignatureExtension(__HrTimerClockBaseVisualizer, "hrtimer_clock_base", "vmlinux"),
            new host.typeSignatureExtension(__HrTimerVisualizer, "hrtimer", "vmlinux"),
            new host.typeSignatureExtension(__TimerBaseVisualizer, "timer_base", "vmlinux"),
            new host.typeSignatureExtension(__TimerListVisualizer, "timer_list", "vmlinux"),

            //*************************************************
            // Function Alias (Command) Records:
            //
            new host.functionAlias(__files, "files"),
            new host.functionAlias(__mount, "mount"),
            new host.functionAlias(__net, "net"),
            new host.functionAlias(__vm, "vm"),
            new host.functionAlias(__log, "log"),
            new host.functionAlias(__dev, "dev"),
            new host.functionAlias(__percpu, "percpu"),
            new host.functionAlias(__allpercpu, "allpercpu"),
            new host.functionAlias(__percpu, "lx_per_cpu"),
            new host.functionAlias(__timer, "timer"),

            ];
}
