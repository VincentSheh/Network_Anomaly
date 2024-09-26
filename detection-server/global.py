import numpy as np
from flask import Flask, request, jsonify, send_file, Response
import pandas as pd
import pickle
from io import StringIO
from sklearn.metrics import *
import os
from deepod.models import PReNet

# Initialize Flask app
app = Flask(__name__)
# def load_model():
# Load XGBoost:
# model = XGBClassifier(objective='binary:logistic')
# model.load_model("./clf_loc_xgboost.json")  
# Load Cart:
with open('PReNet_cpu.pkl', 'rb') as file:
  model = pickle.load(file)

def validated_req_schema(flow_df):
  pruned_features=['Init_Win_bytes_forward', 'Bwd Packets/s',
       'Init_Win_bytes_backward', 'Flow Duration', 'Packet Length Std',
       'PSH Flag Count', #TODO
       'Fwd Packets/s', #TODO
      #  'Destination Port', 
      #  'min_seg_size_forward', #TODO
       'Average Packet Size', 
       'Total Length of Bwd Packets', 'Bwd Packet Length Min',
      #  'Fwd IAT Min', #TODO zero variance columns
       'Fwd Header Length', 'Total Backward Packets',
       'Total Length of Fwd Packets', 
       'Bwd Packet Length Mean',
       'Bwd Header Length', #TODO
      #  'Packet Length Mean', #TODO SIMILAR To Average Packet Size?
       'Flow IAT Min',
       'Flow IAT Max',
       'Flow IAT Total',
       ]
  # Added
  # Flow IAT Max, Flow IAT Total, Fwd IAT Min, PSH Flag Count, Fwd Packets/s
  # Bwd Header Length, 
    # Check for missing columns
  missing_features = [feature for feature in pruned_features if feature not in flow_df.columns]
  if missing_features:
      return f"Missing features in the input data: {', '.join(missing_features)}"  

  
  df_pruned = flow_df[pruned_features]
  print(df_pruned.shape)
        
  return df_pruned  

  
def perform_inference_sup(df): #TODO Change opt_threshold and add standard scaler
  anomaly_scores = model.decision_function(df.to_numpy())

  opt_threshold = 4.6533
  pred = np.where(anomaly_scores > opt_threshold, 1,0)
  pred_df = pd.DataFrame(pred, columns=["Label"])
  labeled_df = df.join(pred_df)
  return labeled_df


@app.route('/upload-csv', methods=['POST'])
def upload_csv():
    csv_dest = "global.csv"
    print("I RUN")
    # Check if a file is part of the POST request
    if 'file' not in request.files:
        return "No file part", 400
    
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    print("I RUN")  
    
    if file:
        # Convert the file stream directly to a DataFrame
        string_data = StringIO(file.read().decode('utf-8'))
        df = pd.read_csv(string_data)
        pruned_df = validated_req_schema(df)
        if not isinstance(pruned_df, pd.DataFrame):
          print(pruned_df)
          return
        
        labeled_df = perform_inference_sup(pruned_df)
        exists = True if os.path.isfile(csv_dest) else False
        
        labeled_df.to_csv(csv_dest, mode='a', header = not exists, index = False)
        # Example processing: return the DataFrame's shape
        # Convert DataFrame to json
        
        resp = labeled_df.to_json(orient='split')
        return jsonify(resp)
        
  

if __name__ == '__main__':
  app.run(host='0.0.0.0', port = 3002, threaded=True)