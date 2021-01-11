import React, { useState } from 'react'
import LoginForm from './components/LoginForm'
import { Status } from "./components/Status";
import { Profile } from "./components/Profile";
import { Provider } from 'react-redux'
import { configureStore, combineReducers } from '@reduxjs/toolkit'
import { user } from './reducers/user'

const URL = "http://localhost:8081/users";

const reducer = combineReducers({ user: user.reducer });

const store = configureStore({ reducer });

export const App = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  // To sign up a user.
  const handleSubmit = (event) => {
    event.preventDefault();

    fetch(URL, {
      method: "POST",
      body: JSON.stringify({ username, password }),
      headers: { "Content-Type": "application/json" },
    })
      .then((res) => res.json())
      .then((json) => console.log(json))
      .catch((err) => console.log("error:", err));
  };
  return (
    <Provider store={store}>
      <Status />
      <Profile />
      <LoginForm />
    </Provider>
  );
};
