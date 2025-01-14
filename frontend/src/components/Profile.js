import React, { useState, useEffect } from 'react'
import { user } from '../reducers/user'
import { useDispatch, useSelector } from 'react-redux'

const URL = 'http://localhost:8080/users'
export const Profile = () => {
  const dispatch = useDispatch()
  const accessToken = useSelector((store) => store.user.login.accessToken)
  const userId = useSelector((store) => store.user.login.userId)
  const statusMessage = useSelector((store) => store.user.login.statusMessage)

  const loginSuccess = (loginResponse) => {}

  const loginFailed = (loginError) => {}

  const logout = () => {}

  const login = () => {
    // Include userId in the path
    fetch(`${URL}/${userId}`, {
      method: 'GET',
      // Include the accessToken to get the protected endpoint
      headers: { Authorization: accessToken },
    })
      .then((res) => {
        if (!res.ok) {
          throw 'Profile test failed'
        }
        return res.json()
      })
      // SUCCESS: Do something with the information we got back
      .then((json) => loginSuccess(json))
      .catch((err) => loginFailed(err)) //401
  }
  if (!accessToken) {
    return <></>
  }

  return (
    <section>
      <h2>Profile:</h2>
      <h4>userId:</h4>
      <p> {`${userId}`}</p>
      <h4>accessToken:</h4>
      <p> {`${accessToken}`}</p>
      <input type="submit" onClick={login} value="Test Login" />
      <input type="submit" onClick={logout} value="Test Logout" />
    </section>
  )
}
export default Profile