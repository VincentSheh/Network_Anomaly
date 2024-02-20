import numpy as np
from flask import Flask, request, jsonify
import pandas as pd
from xgboost import XGBClassifier

# Initialize Flask app
app = Flask(__name__)
# def load_model():
model = XGBClassifier(objective='binary:logistic')
model.load_model("./xgboost_ids.json")  

def decode_json(request):
  data = request.json
  return data
def validated_req_schema(flow_data):
  pruned_features=['Init_Win_bytes_forward', 'Bwd Packets/s',
       'Init_Win_bytes_backward', 'Flow Duration', 'Packet Length Std',
      #  'PSH Flag Count', #TODO
      #  'Fwd Packets/s', #TODO
       'Destination Port', 
      #  'min_seg_size_forward', #TODO
       'Average Packet Size', 
       'Total Length of Bwd Packets', 'Bwd Packet Length Min',
      #  'Fwd IAT Min', #TODO
       'Fwd Header Length', 'Total Backward Packets',
       'Total Length of Fwd Packets', 
       'Bwd Packet Length Mean',
      #  'Bwd Header Length', #TODO
      #  'Packet Length Mean', #TODO SIMILAR To Average Packet Size?
       'Flow IAT Min']
  # Added
  # Flow IAT Max, Flow IAT Total, Fwd IAT Min, PSH Flag Count, Fwd Packets/s
  # Bwd Header Length, 

  df = pd.DataFrame([flow_data])
  df['Destination Port'] = df['Destination Port'].astype(int)
  # Select only the required columns
  df_pruned = df[pruned_features]
      
  return df_pruned  

def perform_inference_sup(x):
  output = model.predict(x)  
  return False if output == 0 else True

def perform_inference_unsup(flow_data):
  pass

@app.route("/detect", methods=['POST'])
def detect():
    flow_data = decode_json(request)
    # print(flow_data)
    input = validated_req_schema(flow_data)    
    isMalicious = perform_inference_sup(input)
    
    

    # result = model.predict(park_img, classes=3, conf = 0.4, save=True, verbose=False)
    # ill_result = model.predict(ill_park_img, classes=3, conf = 0.5, save=False , verbose =False)
    return jsonify({"isMalicious": isMalicious}), 200
  

if __name__ == '__main__':
  app.run(host='0.0.0.0', port = 3001, threaded=True)