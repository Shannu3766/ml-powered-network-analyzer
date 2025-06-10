import streamlit as st
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import pandas as pd
import time
import numpy as np
import joblib
import threading
import queue
import winsound  # For Windows sound alerts
from datetime import datetime
import os

# Get the project root directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

flows = defaultdict(list)
packet_count = 0
MAX_PACKETS = 10  # Capture limit
prediction_queue = queue.Queue()
is_capturing = False
ALARM_THRESHOLD = [1,2,3,4,5,6,7,8,9, 10, 11]  
# ALARM_THRESHOLD = [0,1,2,3,4,5,6,7,8]
capture_stats = {
    'total_packets': 0,
    'total_flows': 0,
    'start_time': None,
    'last_update': None
}

def get_flow_key(pkt):
    if IP in pkt and (TCP in pkt or UDP in pkt):
        proto = "TCP" if TCP in pkt else "UDP"
        sport = pkt[TCP].sport if proto == "TCP" else pkt[UDP].sport
        dport = pkt[TCP].dport if proto == "TCP" else pkt[UDP].dport
        return (pkt[IP].src, pkt[IP].dst, sport, dport, proto)
    return None

def process_packet(pkt):
    global packet_count, flows
    if packet_count >= MAX_PACKETS:
        return True  

    key = get_flow_key(pkt)
    if key:
        flows[key].append({
            'time': pkt.time,
            'len': len(pkt),
            'flags': pkt[TCP].flags if TCP in pkt else '',
            'src': pkt[IP].src,
            'dst': pkt[IP].dst,
            'sport': pkt[TCP].sport if TCP in pkt else pkt[UDP].sport,
            'dport': pkt[TCP].dport if TCP in pkt else pkt[UDP].dport,
            'proto': "TCP" if TCP in pkt else "UDP",
        })
    packet_count += 1

def capture_packets():
    global packet_count, flows, is_capturing, capture_stats
    while is_capturing:
        packet_count = 0
        flows = defaultdict(list)
        capture_stats['start_time'] = datetime.now()
        print(f"Capturing {MAX_PACKETS} packets...")
        sniff(prn=process_packet, store=0, stop_filter=lambda x: packet_count >= MAX_PACKETS)
        capture_stats['total_packets'] += packet_count
        capture_stats['total_flows'] += len(flows)
        capture_stats['last_update'] = datetime.now()
        extract_flow_features()
        time.sleep(1)  

def extract_flow_features():
    flow_features = []
    for key, pkts in flows.items():
        if not pkts:  
            continue
            
        times = np.array([p['time'] for p in pkts])
        lengths = np.array([p['len'] for p in pkts])
        flags = ''.join([str(p['flags']) for p in pkts if 'flags' in p])

       
        duration = times[-1] - times[0] if len(times) > 1 else 0
        num_packets = len(pkts)

        
        fwd_pkts = [p for p in pkts if p['sport'] < p['dport']]
        bwd_pkts = [p for p in pkts if p['sport'] > p['dport']]

     
        fwd_lengths = np.array([p['len'] for p in fwd_pkts])
        bwd_lengths = np.array([p['len'] for p in bwd_pkts])

        
        fwd_iat = np.diff([p['time'] for p in fwd_pkts]) if len(fwd_pkts) > 1 else np.array([0])
        bwd_iat = np.diff([p['time'] for p in bwd_pkts]) if len(bwd_pkts) > 1 else np.array([0])

        
        flow_feature = {
            'Destination Port': key[3],
            'Flow Duration': duration,
            'Total Fwd Packets': len(fwd_pkts),
            'Total Backward Packets': len(bwd_pkts),
            'Total Length of Fwd Packets': np.sum(fwd_lengths),
            'Total Length of Bwd Packets': np.sum(bwd_lengths),
            'Fwd Packet Length Max': np.max(fwd_lengths) if len(fwd_lengths) > 0 else 0,
            'Fwd Packet Length Min': np.min(fwd_lengths) if len(fwd_lengths) > 0 else 0,
            'Fwd Packet Length Mean': np.mean(fwd_lengths) if len(fwd_lengths) > 0 else 0,
            'Fwd Packet Length Std': np.std(fwd_lengths) if len(fwd_lengths) > 0 else 0,
            'Bwd Packet Length Max': np.max(bwd_lengths) if len(bwd_lengths) > 0 else 0,
            'Bwd Packet Length Min': np.min(bwd_lengths) if len(bwd_lengths) > 0 else 0,
            'Bwd Packet Length Mean': np.mean(bwd_lengths) if len(bwd_lengths) > 0 else 0,
            'Bwd Packet Length Std': np.std(bwd_lengths) if len(bwd_lengths) > 0 else 0,
            'Flow Bytes/s': np.sum(lengths) / duration if duration > 0 else 0,
            'Flow Packets/s': num_packets / duration if duration > 0 else 0,
            'Flow IAT Mean': np.mean(np.diff(times)) if len(times) > 1 else 0,
            'Flow IAT Std': np.std(np.diff(times)) if len(times) > 1 else 0,
            'Flow IAT Max': np.max(np.diff(times)) if len(times) > 1 else 0,
            'Flow IAT Min': np.min(np.diff(times)) if len(times) > 1 else 0,
            'Fwd IAT Total': np.sum(fwd_iat),
            'Fwd IAT Mean': np.mean(fwd_iat) if len(fwd_iat) > 0 else 0,
            'Fwd IAT Std': np.std(fwd_iat) if len(fwd_iat) > 0 else 0,
            'Fwd IAT Max': np.max(fwd_iat) if len(fwd_iat) > 0 else 0,
            'Fwd IAT Min': np.min(fwd_iat) if len(fwd_iat) > 0 else 0,
            'Bwd IAT Total': np.sum(bwd_iat),
            'Bwd IAT Mean': np.mean(bwd_iat) if len(bwd_iat) > 0 else 0,
            'Bwd IAT Std': np.std(bwd_iat) if len(bwd_iat) > 0 else 0,
            'Bwd IAT Max': np.max(bwd_iat) if len(bwd_iat) > 0 else 0,
            'Bwd IAT Min': np.min(bwd_iat) if len(bwd_iat) > 0 else 0,
            'Fwd PSH Flags': flags.count('P'),
            'Bwd PSH Flags': flags.count('P'),
            'Fwd URG Flags': flags.count('U'),
            'Bwd URG Flags': flags.count('U'),
            'Fwd Header Length': np.sum([len(p) for p in fwd_pkts]),
            'Bwd Header Length': np.sum([len(p) for p in bwd_pkts]),
            'Fwd Packets/s': len(fwd_pkts) / duration if duration > 0 else 0,
            'Bwd Packets/s': len(bwd_pkts) / duration if duration > 0 else 0,
            'Min Packet Length': np.min(lengths) if len(lengths) > 0 else 0,
            'Max Packet Length': np.max(lengths) if len(lengths) > 0 else 0,
            'Packet Length Mean': np.mean(lengths) if len(lengths) > 0 else 0,
            'Packet Length Std': np.std(lengths) if len(lengths) > 0 else 0,
            'Packet Length Variance': np.var(lengths) if len(lengths) > 0 else 0,
            'FIN Flag Count': flags.count('F'),
            'SYN Flag Count': flags.count('S'),
            'RST Flag Count': flags.count('R'),
            'PSH Flag Count': flags.count('P'),
            'ACK Flag Count': flags.count('A'),
            'URG Flag Count': flags.count('U'),
            'CWE Flag Count': flags.count('C'),
            'ECE Flag Count': flags.count('E'),
            'Down/Up Ratio': (np.sum(bwd_lengths) / np.sum(fwd_lengths)) if np.sum(fwd_lengths) > 0 else 0,
            'Average Packet Size': np.mean(lengths) if len(lengths) > 0 else 0,
            'Avg Fwd Segment Size': np.mean(fwd_lengths) if len(fwd_lengths) > 0 else 0,
            'Avg Bwd Segment Size': np.mean(bwd_lengths) if len(bwd_lengths) > 0 else 0,
            'Fwd Header Length.1': np.sum([len(p) for p in fwd_pkts]),
            'Fwd Avg Bytes/Bulk': np.mean(fwd_lengths) / len(fwd_pkts) if len(fwd_pkts) > 0 else 0,
            'Fwd Avg Packets/Bulk': len(fwd_pkts) / len(fwd_pkts) if len(fwd_pkts) > 0 else 0,
            'Fwd Avg Bulk Rate': np.mean(fwd_lengths) / duration if duration > 0 else 0,
            'Bwd Avg Bytes/Bulk': np.mean(bwd_lengths) / len(bwd_pkts) if len(bwd_pkts) > 0 else 0,
            'Bwd Avg Packets/Bulk': len(bwd_pkts) / len(bwd_pkts) if len(bwd_pkts) > 0 else 0,
            'Bwd Avg Bulk Rate': np.mean(bwd_lengths) / duration if duration > 0 else 0,
            'Subflow Fwd Packets': len(fwd_pkts),
            'Subflow Fwd Bytes': np.sum(fwd_lengths),
            'Subflow Bwd Packets': len(bwd_pkts),
            'Subflow Bwd Bytes': np.sum(bwd_lengths),
        }
        flow_features.append(flow_feature)

    if flow_features:
        df = pd.DataFrame(flow_features)
        predict_flows(df)

def predict_flows(df):
    try:
        # Update model paths to use the new structure
        model_path = os.path.join(PROJECT_ROOT, 'models', 'random_forest.pkl')
        label_encoder_path = os.path.join(PROJECT_ROOT, 'models', 'label_encoder.pkl')
        scaler_path = os.path.join(PROJECT_ROOT, 'models', 'scaler.pkl')
        
        rf = joblib.load(model_path)
        le = joblib.load(label_encoder_path)
        scaler = joblib.load(scaler_path)

        
        features = df.columns
        X = df[features]

       
        X_scaled = scaler.transform(X)

        
        predictions = rf.predict(X_scaled)
        df['Prediction'] = predictions
        alarm_conditions = df['Prediction'].isin(ALARM_THRESHOLD)
        
        predicted_labels = le.inverse_transform(predictions)

        
        df['Predicted Label'] = predicted_labels

        if alarm_conditions.any():
            detected_thresholds = df[alarm_conditions]['Predicted Label'].unique()
            detected_thresholds.sort()
            threshold_str = ', '.join(map(str, detected_thresholds))
            
           
            winsound.Beep(1000, 1000)  
            prediction_queue.put((df, True, threshold_str))  
        else:
            prediction_queue.put((df, False, None))
    except Exception as e:
        st.error(f"Error in prediction: {str(e)}")

def main():
    st.set_page_config(page_title="Network Traffic Analysis", layout="wide")
    
   
    st.title("Network Traffic Analysis")
    st.write("This application captures network packets and predicts their types using machine learning.")
    
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        
        results_placeholder = st.empty()
        alarm_placeholder = st.empty()
    
    with col2:
        
        st.subheader("Capture Status")
        status_placeholder = st.empty()
        stats_placeholder = st.empty()
        
       
        if 'capturing' not in st.session_state:
            st.session_state.capturing = False

        if st.button('Start/Stop Capture', type='primary'):
            st.session_state.capturing = not st.session_state.capturing
            global is_capturing
            is_capturing = st.session_state.capturing
            
            if st.session_state.capturing:
                
                capture_stats['total_packets'] = 0
                capture_stats['total_flows'] = 0
                capture_stats['start_time'] = datetime.now()
                
                capture_thread = threading.Thread(target=capture_packets)
                capture_thread.daemon = True
                capture_thread.start()
            else:
                st.write("Capture stopped")


    while st.session_state.capturing:
        try:
            
            with status_placeholder:
                st.markdown("""
                <style>
                .capturing {
                    animation: pulse 1s infinite;
                }
                @keyframes pulse {
                    0% { opacity: 1; }
                    50% { opacity: 0.5; }
                    100% { opacity: 1; }
                }
                </style>
                """, unsafe_allow_html=True)
                st.markdown('<div class="capturing">🟢 Capturing...</div>', unsafe_allow_html=True)
            
            
            with stats_placeholder:
                if capture_stats['start_time']:
                    duration = datetime.now() - capture_stats['start_time']
                    st.metric("Capture Duration", f"{duration.seconds} seconds")
                    st.metric("Total Packets", capture_stats['total_packets'])
                    st.metric("Total Flows", capture_stats['total_flows'])
                    if capture_stats['last_update']:
                        st.metric("Last Update", capture_stats['last_update'].strftime("%H:%M:%S"))
            
            if not prediction_queue.empty():
                df, alarm_triggered, threshold_str = prediction_queue.get()
                with results_placeholder:
                    st.subheader("Latest Predictions")
                    st.dataframe(df, use_container_width=True)
                
                if alarm_triggered:
                    alarm_placeholder.error(f"""
                    🚨 ALARM: Suspicious traffic detected!
                    
                    Detected threshold values: {threshold_str}
                    
                    Please check the network traffic immediately!
                    """)
                else:
                    alarm_placeholder.empty()
        except Exception as e:
            st.error(f"Error displaying results: {str(e)}")
        time.sleep(0.1)

if __name__ == "__main__":
    main()
