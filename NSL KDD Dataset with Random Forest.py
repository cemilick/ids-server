#!/usr/bin/env python
# coding: utf-8

# # Import Common Package

# In[1]:


import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from jcopml.utils import save_model, load_model


# # Import Data

# In[2]:


import sklearn
print('sklearn = {}',sklearn.__version__)
np.__version__
pd.__version__
sns.__version__


# In[3]:


df = pd.read_csv('./nsl-kdd/KDDTrain+.txt')
df.head()


# # Set Column for the Dataset

# In[4]:


columns = (['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot'
,'num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations'
,'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count','serror_rate'
,'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count'
,'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate'
,'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate','outcome','level'])


# ## Normalization for Outcome

# In[5]:


df.columns = columns
df.drop(columns=['flag','land','wrong_fragment','urgent','hot'
,'num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations'
,'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count','serror_rate'
,'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count'
,'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate'
,'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate', 'level'], inplace=True)
df.loc[df['outcome'] == "normal", "outcome"] = 0
df.loc[df['outcome'] != 0, "outcome"] = 1


# In[6]:


pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)
df.head(100)


# # Dataset Splitting

# In[7]:


from sklearn.model_selection import train_test_split


# In[8]:


X = df.drop(columns="outcome")
y = df.outcome

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

y_train = y_train.astype('int')
y_test = y_test.astype('int')
X_train.shape, X_test.shape, y_train.shape, y_test.shape


# # Data Preprocessing 

# In[9]:


from sklearn.preprocessing import MinMaxScaler, OneHotEncoder, PolynomialFeatures


# ## Create Pipeline for Scaler and Imputer

# In[10]:


num_pip = Pipeline([
    ("imputer", SimpleImputer(strategy="mean")),
    ("scaler", MinMaxScaler()),
    ("poly", PolynomialFeatures())
])

cat_pip = Pipeline([
    ("imputer", SimpleImputer(strategy="most_frequent")),
    ("onehot", OneHotEncoder(handle_unknown='ignore'))
])


# ## Add column into pipeline

# In[11]:


from sklearn.compose import ColumnTransformer


# In[12]:


cat_cols = ['protocol_type','service']
num_cols = ['duration', 'src_bytes', 'dst_bytes']

preprocessor = ColumnTransformer([
        ("numeric", num_pip, num_cols),
        ("categoric", cat_pip, cat_cols)
    ])


# # Training

# In[13]:


from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV
from jcopml.tuning import random_search_params as rsp


# In[14]:


pipeline = Pipeline([
    ('prep', preprocessor),
    ('algo', RandomForestClassifier(n_jobs=-1, random_state=42))
])

model = RandomizedSearchCV(pipeline, rsp.rf_poly_params, cv=3, n_iter=50, n_jobs=-1, verbose=1, random_state=42)


# In[15]:


rsp.rf_poly_params


# In[16]:


model.fit(X_train, y_train)


# In[17]:


# print(model.best_params_)
print(model.score(X_train, y_train), model.best_score_ ,model.score(X_test, y_test))


# # Model without Hyperparameter Tuning

# In[18]:


model2 = pipeline


# In[19]:


model2.fit(X_train, y_train)


# In[20]:


# print(model.best_params_)
print(model2.score(X_train, y_train), model2.score(X_test, y_test))


# In[21]:


save_model(model.best_estimator_, "rf_nsl_with_hyperparams_estimator.pkl")
save_model(model, "rf_nsl_with_hyperparams_model.pkl")
save_model(model2, "rf_nsl_without_hyperparams.pkl")


# In[ ]:




