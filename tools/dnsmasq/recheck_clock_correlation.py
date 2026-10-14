#!/usr/bin/env python3
"""Correlate historical synthetic DNS failures with conntrack warnings.

The clock model is calibrated exclusively from later observer clock samples;
old DNS completion/kernel events never influence its offset or slope. Raw
router logs stay private. This is correlation, not per-packet attribution.
"""
import argparse
import collections
import hashlib
import json
import re
import statistics
import struct
from pathlib import Path

RECORD=struct.Struct('<QQQHHBBBB')
WINDOWS=('main-run/08-busy-C','capture-run/02-busy-R','retention-run/01-busy-R',
         'retention-run/02-busy-R','retention-run/03-busy-R')
TOLERANCES_MS=(10,25,50,100)
NEGATIVE_SHIFTS_S=(-5,-1,-.5,.5,1,5)

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def rows(path): return [json.loads(line) for line in path.read_text().splitlines() if line]
def warnings(path):
    # Preserve integer nanoseconds and log order; dmesg prints microseconds.
    found=[]
    for line in path.read_text().splitlines():
        m=re.match(r'^\[\s*(\d+)\.(\d+)\] .*nf_conntrack: table full, dropping packet$',line)
        if m: found.append(int(m[1])*10**9+int(m[2].ljust(9,'0')))
    if found!=sorted(found): raise ValueError('nonmonotonic kernel warning timestamps')
    return found

def stats(values):
    if not values:return None
    return {'n':len(values),'min':min(values),'median':statistics.median(values),
            'max':max(values),'mean':statistics.mean(values)}

def one_to_one(predictions,kernel,tolerance):
    # Sorted greedy matching maximizes cardinality for interval compatibility.
    pairs=[];i=j=0
    while i<len(predictions) and j<len(kernel):
        if kernel[j]<predictions[i]-tolerance:j+=1
        elif kernel[j]>predictions[i]+tolerance:i+=1
        else:pairs.append((i,j));i+=1;j+=1
    return pairs

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--old-resource-root',required=True,type=Path)
    p.add_argument('--old-kernel',required=True,type=Path)
    p.add_argument('--observer',required=True,type=Path,action='append')
    p.add_argument('--new-kernel',type=Path)
    p.add_argument('--validation-observer',type=Path,action='append',default=[])
    p.add_argument('--output',required=True,type=Path)
    a=p.parse_args()
    calibration=sorted([r for path in a.observer for r in rows(path)
                        if r.get('event') in ('attached','complete','failure')],key=lambda r:r['monotonic_ns'])
    if len(calibration)<2: raise ValueError('need at least two independent observer clock samples')
    first,last=calibration[0],calibration[-1]
    m0,m1=first['monotonic_ns'],last['monotonic_ns'];r0,r1=first['monotonic_raw_ns'],last['monotonic_raw_ns']
    if m1-m0<30*10**9:raise ValueError('clock calibration span must be at least 30 seconds')
    slope=(r1-r0)/(m1-m0)
    def raw(m):return r0+(m-m0)*slope
    # Independently specified secondary model reveals endpoint sample noise.
    xs=[r['monotonic_ns']-m0 for r in calibration];ys=[r['monotonic_raw_ns']-r0 for r in calibration]
    xm,ym=statistics.mean(xs),statistics.mean(ys)
    ols_slope=sum((x-xm)*(y-ym) for x,y in zip(xs,ys))/sum((x-xm)**2 for x in xs)
    ols_intercept=ym-ols_slope*xm
    def raw_ols(m):return r0+ols_intercept+(m-m0)*ols_slope
    old=warnings(a.old_kernel)
    result={'schema':1,'purpose':'Independent later-clock calibration followed by retrospective event correlation; not historical syscall evidence',
      'limitations':['Dmesg is not assumed a priori to equal CLOCK_MONOTONIC_RAW; new observed send failures check that relationship empirically.',
        'Clock reads are sequential and unbracketed, so residuals are observations, not rigorous timestamp uncertainty bounds.',
        'Affine clock-rate extrapolation backwards cannot exclude historical NTP frequency changes; small residuals are correlation, not a causal proof.',
        'Kernel warnings lack PID/query identity and can be rate limited; unmatched warnings need not belong to this test.',
        'The 17 old C errors lack captured packets and must not be reclassified as REFUSED.'],
      'input_sha256':{'old_kernel':sha(a.old_kernel),'observer':[sha(path) for path in a.observer]},
      'calibration':{'method':'Endpoint affine RAW(MONOTONIC), calibrated only on later independent observer clocks; no fitting to historical DNS/kernel errors',
        'first_clock_record':first,'last_clock_record':last,'span_seconds':(m1-m0)/1e9,
        'raw_per_monotonic_second':slope,'relative_rate_ppm':(slope-1)*1e6,
        'internal_raw_residual_ms':stats([(r['monotonic_raw_ns']-raw(r['monotonic_ns']))/1e6 for r in calibration]),
        'secondary_OLS_raw_per_monotonic_second':ols_slope,
        'boottime_minus_monotonic_ms':stats([(r['boottime_ns']-r['monotonic_ns'])/1e6 for r in calibration])},
      'historical_kernel_warning_count':len(old),'windows':[]}
    all_predictions=[];all_entries=[]
    for folder in WINDOWS:
        path=a.old_resource_root/folder;data=(path/'udp.latencies.bin').read_bytes()
        if len(data)%RECORD.size:raise ValueError(f'incomplete latency file: {path}')
        failures=[row for row in RECORD.iter_unpack(data) if row[5]==2]
        expected=json.loads((path/'udp.json').read_text())['measurement']['wrong']
        if len(failures)!=expected:raise ValueError(f'latency/summary error count mismatch: {path}')
        captured={r['sequence']:r for r in rows(path/'udp.wire-samples.jsonl') if not r['correct']}
        entries=[]
        for row in failures:
            seq,latency,sent,client,qtype,status,phase,kind,_=row
            observed=captured.get(seq);rcode=None
            if observed:
                packet=bytes.fromhex(observed['reply_hex']);query=bytes.fromhex(observed['query_hex']);rcode=packet[3]&15
                if packet[:2]!=query[:2] or packet[12:]!=query[12:] or packet[4:12]!=bytes.fromhex('0001000000000000'):
                    raise ValueError(f'historical error packet does not preserve ID/question: {path} {seq}')
            completion=sent+latency;prediction=raw(completion)
            nearest=sorted(((abs(k-prediction),index,k) for index,k in enumerate(old)))[:2]
            entries.append({'sequence':seq,'send_monotonic_ns':sent,'completion_monotonic_ns':completion,
                'response_rcode_if_captured':rcode,'predicted_kernel_ns':round(prediction),
                'closest_kernel_index':nearest[0][1],'closest_kernel_ns':nearest[0][2],
                'completion_minus_closest_kernel_ms':(prediction-nearest[0][2])/1e6,
                'second_closest_distance_ms':nearest[1][0]/1e6,
                'candidate_kernel_events_within_10ms':sum(abs(k-prediction)<=10e6 for k in old),
                'endpoint_minus_OLS_prediction_ms':(prediction-raw_ols(completion))/1e6})
        predictions=sorted(raw(r[2]+r[1]) for r in failures)
        all_predictions+=predictions;all_entries+=entries
        result['windows'].append({'window':folder,'implementation':'C' if folder.endswith('-C') else 'R_old',
            'latencies_sha256':sha(path/'udp.latencies.bin'),'wire_samples_sha256':sha(path/'udp.wire-samples.jsonl'),
            'wrong_completions':len(entries),'captured_refused':sum(e['response_rcode_if_captured']==5 for e in entries),
            'unrecorded_error_packets':sum(e['response_rcode_if_captured'] is None for e in entries),
            'one_to_one_counts_by_tolerance_ms':{str(t):len(one_to_one(predictions,old,t*10**6)) for t in TOLERANCES_MS},
            'closest_event_residual_ms':stats([e['completion_minus_closest_kernel_ms'] for e in entries]),
            'events':entries})
    all_predictions.sort()
    result['historical_total']={'wrong_completions':len(all_entries),'captured_refused':sum(e['response_rcode_if_captured']==5 for e in all_entries),
        'distinct_nearest_kernel_events':len({e['closest_kernel_index'] for e in all_entries}),
        'events_with_multiple_kernel_candidates_within_10ms':sum(e['candidate_kernel_events_within_10ms']>1 for e in all_entries),
        'closest_event_residual_ms':stats([e['completion_minus_closest_kernel_ms'] for e in all_entries]),
        'endpoint_minus_OLS_prediction_ms':stats([e['endpoint_minus_OLS_prediction_ms'] for e in all_entries]),
        'backwards_extrapolation_seconds':stats([(m0-e['completion_monotonic_ns'])/1e9 for e in all_entries]),
        'one_to_one_counts_by_tolerance_ms':{str(t):len(one_to_one(all_predictions,old,t*10**6)) for t in TOLERANCES_MS},
        'fixed_time_shift_negative_controls':[
          {'shift_seconds':shift,'counts_by_tolerance_ms':{str(t):len(one_to_one([x+shift*1e9 for x in all_predictions],old,t*10**6)) for t in TOLERANCES_MS}}
          for shift in NEGATIVE_SHIFTS_S]}
    if a.new_kernel:
        newer=warnings(a.new_kernel);result['input_sha256']['new_kernel']=sha(a.new_kernel)
        actual=[r for r in calibration if r.get('event')=='failure' and r.get('syscall')=='sendto'
                and r.get('errno')==1 and r.get('destination')=='127.0.0.1:15354']
        offsets=[min(newer,key=lambda k:abs(k-r['monotonic_raw_ns']))-r['monotonic_raw_ns'] for r in actual]
        result['new_EPERM_kernel_clock_check']={'observed_EPERM_sends':len(actual),
            'raw_minus_nearest_kernel_ms':stats([-x/1e6 for x in offsets]),
            'one_to_one_counts_by_tolerance_ms':{str(t):len(one_to_one(sorted(r['monotonic_raw_ns'] for r in actual),newer,t*10**6)) for t in TOLERANCES_MS}}
        if offsets:
            offset=statistics.median(offsets)
            corrected=[x+offset for x in all_predictions]
            result['contemporaneous_offset_sensitivity']={
                'method':'Add median current EPERM warning-minus-RAW offset; never fitted to historical errors. Not a rigorous clock bound.',
                'kernel_minus_raw_offset_ms':offset/1e6,
                'old_closest_event_residual_ms':stats([(x-min(old,key=lambda k:abs(k-x)))/1e6 for x in corrected]),
                'one_to_one_counts_by_tolerance_ms':{str(t):len(one_to_one(corrected,old,t*10**6)) for t in TOLERANCES_MS}}
    if a.validation_observer:
        result['external_clock_validation']=[]
        result['input_sha256']['validation_observer']=[sha(path) for path in a.validation_observer]
        for path in a.validation_observer:
            samples=[r for r in rows(path) if r.get('event') in ('attached','complete','failure')]
            validation={'source_sha256':sha(path),'clock_samples':len(samples),
                'method':'Held-out clock samples; original R-only endpoint model unchanged',
                'raw_residual_against_R_only_model_ms':stats([(r['monotonic_raw_ns']-raw(r['monotonic_ns']))/1e6 for r in samples]),
                'elapsed_from_R_calibration_start_seconds':stats([(r['monotonic_ns']-m0)/1e9 for r in samples])}
            if a.new_kernel:
                actual=[r for r in samples if r.get('event')=='failure' and r.get('syscall')=='sendto'
                        and r.get('errno')==1 and r.get('destination')=='127.0.0.1:15354']
                validation['observed_EPERM_sends']=len(actual)
                validation['raw_minus_nearest_kernel_ms']=stats([(r['monotonic_raw_ns']-min(newer,key=lambda k:abs(k-r['monotonic_raw_ns'])))/1e6 for r in actual])
                validation['one_to_one_counts_by_tolerance_ms']={str(t):len(one_to_one(sorted(r['monotonic_raw_ns'] for r in actual),newer,t*10**6)) for t in TOLERANCES_MS}
            result['external_clock_validation'].append(validation)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k in ('calibration','historical_total','new_EPERM_kernel_clock_check','contemporaneous_offset_sensitivity','external_clock_validation')},indent=2))
if __name__=='__main__': main()
