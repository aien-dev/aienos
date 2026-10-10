// scripts/iort_decode.rs: read-only ACPI IORT decoder (host tool, std only, no deps).
// Build: rustc --edition 2021 -O -o iort_decode scripts/iort_decode.rs
// Run:   sudo cat /sys/firmware/acpi/tables/IORT > IORT.bin && ./iort_decode IORT.bin [segment rid_hex]
// Layout: linux include/acpi/actbl2.h (packed), ARM DEN 0049. ID ranges are inclusive
// (id_count = number of ids minus one), as linux drivers/acpi/arm64/iort.c iort_id_map does.
// Added for aienos#286 cut B5 (docs/GB10_IORT_DECODE.md). Reads a file; touches no hardware.
// Read-only ACPI IORT decoder (layout: linux include/acpi/actbl2.h, ARM DEN 0049, packed).
use std::fs; use std::env;
fn u8_(b:&[u8],o:usize)->u8{b[o]} fn u16_(b:&[u8],o:usize)->u16{u16::from_le_bytes([b[o],b[o+1]])}
fn u32_(b:&[u8],o:usize)->u32{u32::from_le_bytes(b[o..o+4].try_into().unwrap())}
fn u64_(b:&[u8],o:usize)->u64{u64::from_le_bytes(b[o..o+8].try_into().unwrap())}
#[derive(Clone)] struct Map{ib:u32,cnt:u32,ob:u32,oref:u32,fl:u32}
#[derive(Clone)] struct Node{off:usize,ty:u8,len:u16,id:u32,maps:Vec<Map>,seg:Option<u32>,smmu_base:Option<u64>,name:Option<String>}
fn main(){
  let a:Vec<String>=env::args().collect(); let b=fs::read(&a[1]).unwrap();
  assert_eq!(&b[0..4],b"IORT"); let tlen=u32_(&b,4) as usize; assert_eq!(tlen,b.len());
  let rev=u8_(&b,8); let ncount=u32_(&b,36) as usize; let noff=u32_(&b,40) as usize;
  println!("IORT len={} rev={} oem={} node_count={} node_offset={}",tlen,rev,String::from_utf8_lossy(&b[10..16]).trim(),ncount,noff);
  let mut nodes=Vec::new(); let mut o=noff;
  for _ in 0..ncount{
    let ty=u8_(&b,o); let len=u16_(&b,o+1) as usize; let id=u32_(&b,o+4); let mc=u32_(&b,o+8) as usize; let mo=u32_(&b,o+12) as usize;
    let mut n=Node{off:o,ty,len:len as u16,id,maps:vec![],seg:None,smmu_base:None,name:None};
    let d=o+16; // node_data
    match ty{
      2=>{ n.seg=Some(u32_(&b,d+12)); println!("node@{:#06x} type=2 PCI_ROOT_COMPLEX id={} len={} memprops={:#x} ats={} segment={} addr_limit={} maps={}",o,id,len,u64_(&b,d),u32_(&b,d+8),u32_(&b,d+12),u8_(&b,d+16),mc); }
      4=>{ n.smmu_base=Some(u64_(&b,d)); println!("node@{:#06x} type=4 SMMU_V3 id={} len={} base={:#x} flags={:#x} model={} event_gsiv={} pri={} gerr={} sync={} pxm={} idmap_index={} maps={}",o,id,len,u64_(&b,d),u32_(&b,d+8),u32_(&b,d+24),u32_(&b,d+28),u32_(&b,d+32),u32_(&b,d+36),u32_(&b,d+40),u32_(&b,d+44),u32_(&b,d+48),mc); }
      0=>{ let c=u32_(&b,d) as usize; let ids:Vec<String>=(0..c).map(|i|format!("{}",u32_(&b,d+4+4*i))).collect(); println!("node@{:#06x} type=0 ITS_GROUP id={} len={} its_ids=[{}] maps={}",o,id,len,ids.join(","),mc); }
      1=>{ let s=&b[d+13..o+len]; let name=String::from_utf8_lossy(&s[..s.iter().position(|&c|c==0).unwrap_or(s.len())]).to_string(); n.name=Some(name.clone()); println!("node@{:#06x} type=1 NAMED_COMPONENT id={} len={} flags={:#x} memprops={:#x} addr_limit={} name={} maps={}",o,id,len,u32_(&b,d),u64_(&b,d+4),u8_(&b,d+12),name,mc); }
      5=>{ println!("node@{:#06x} type=5 PMCG id={} len={} page0={:#x} ovf_gsiv={} node_ref={:#x} maps={}",o,id,len,u64_(&b,d),u32_(&b,d+8),u32_(&b,d+12),mc); }
      6=>{ let fl=u32_(&b,d); let rc=u32_(&b,d+4) as usize; let ro=u32_(&b,d+8) as usize; println!("node@{:#06x} type=6 RMR id={} len={} flags={:#x} rmr_count={} maps={}",o,id,len,fl,rc,mc); for i in 0..rc{ let r=o+ro+20*i; println!("   rmr[{}] base={:#x} len={:#x}",i,u64_(&b,r),u64_(&b,r+8)); } }
      t=>{ println!("node@{:#06x} type={} (undecoded) id={} len={} maps={}",o,t,id,len,mc); }
    }
    for i in 0..mc{ let m=o+mo+20*i; let mp=Map{ib:u32_(&b,m),cnt:u32_(&b,m+4),ob:u32_(&b,m+8),oref:u32_(&b,m+12),fl:u32_(&b,m+16)};
      println!("   map[{}] in={:#x}..={:#x} out={:#x} -> node@{:#06x} flags={:#x}{}",i,mp.ib,mp.ib.wrapping_add(mp.cnt),mp.ob,mp.oref,mp.fl,if mp.fl&1==1{" (single)"}else{""}); n.maps.push(mp);}
    nodes.push(n); o+=len;
  }
  if a.len()>3 { let seg:u32=a[2].parse().unwrap(); let rid=u32::from_str_radix(a[3].trim_start_matches("0x"),16).unwrap();
    println!("\nRESOLVE segment={} rid={:#06x}",seg,rid);
    let rc=nodes.iter().find(|n|n.ty==2&&n.seg==Some(seg)); let Some(mut cur)=rc.cloned() else {println!("  no root complex for segment {}",seg); return;};
    let mut idv=rid; let mut hops=0;
    loop{ hops+=1; if hops>8{println!("  loop guard");break;}
      let m=cur.maps.iter().find(|m| m.fl&1==0 && idv>=m.ib && idv <= m.ib.wrapping_add(m.cnt));
      let Some(m)=m else { println!("  node@{:#06x} type={}: no mapping covers id {:#x} -> UNMAPPED",cur.off,cur.ty,idv); break; };
      let out=m.ob + (idv-m.ib); let Some(next)=nodes.iter().find(|n|n.off==m.oref as usize) else {println!("  dangling ref {:#x}",m.oref);break;};
      println!("  node@{:#06x} type={} id {:#x} -> node@{:#06x} type={} id {:#x}{}",cur.off,cur.ty,idv,next.off,next.ty,out, match (next.ty,next.smmu_base){(4,Some(bs))=>format!("  [SMMUv3 base {:#x}, StreamID {:#x}]",bs,out),(0,_)=>"  [ITS group, DeviceID]".to_string(),_=>String::new()});
      idv=out; cur=next.clone(); if cur.maps.is_empty(){break;}
    }
  }
}
