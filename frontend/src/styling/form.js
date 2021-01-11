import styled from 'styled-components'


export const LoginSection = styled.div`
display: flex;
justify-content: center;
box-sizing: border-box;
  height: 100%;
  display: flex;
  width: 100%;
  border-radius: 20px;

  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
`

export const Form = styled.form`
box-sizing: border-box;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  width: 40%;
  border-radius: 20px;
  margin: 10px;
`

export const Button = styled.button`
box-sizing: border-box;
  display: inline-block;
  text-align: center;
  width: 100px;
  border-radius: 20px;
  padding: 10px;
  margin-top: 15px;
  background: #3FB1B5;
  color: #fff;
  border: none;
`
export const SignUpImage = styled.img`
box-sizing: border-box;
  width: 60%;
  object-fit: cover;
`
export const LoginInput = styled.input`
height: 35px;
border: none;
border-bottom: 2px solid #DDDDDD;
`

export const InputLabel = styled.label`
display:flex;
flex-direction: column;
box-sizing: border-box;
  display: flex;
  width: 60%;
  border-radius: 20px;
  margin: 10px;
`




