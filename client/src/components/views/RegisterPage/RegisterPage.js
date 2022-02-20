import React,{useState} from 'react'
import {useDispatch} from 'react-redux';
import {withRouter} from 'react-router-dom';
import {registerUser} from  '../../../_actions/user_action'

function RegisterPage(props) {
  const dispatch = useDispatch();
  const [Email, setEmail] = useState("")
  const [Password, setPassword] = useState("")
  const [Name, setName] = useState("")
  const [ConfirmPassword, setConfirmPassword] = useState("")

  const onEmailHandler = (event) => {
    setEmail(event.currentTarget.value)
  }

  const onNameHandler = (event)=>{
    setName(event.currentTarget.value)
  }

  const onPasswordHandler = (event)=>{
    setPassword(event.currentTarget.value)
  }

  const onConfirmPasswordHandler = (event)=>{
    setConfirmPassword(event.currentTarget.value)
  }


  const onSubmitHandler=(event)=>{
    event.preventDefault();
    if (Password !==ConfirmPassword){
      return alert('Password and Confirm Password doe not match')
    }

    let body = {
      email:Email,
      name:Name,
      password:Password,
      confirmPassword : ConfirmPassword
    }

    dispatch(registerUser(body))
      .then(response => {
      
      if(response.payload.success){
          props.history.push('/login')
          alert('회원가입 완료, 로그인 페이지로 이동합니다')
      } else {
        alert('Failed to sign up')
      }
    
    })
  }
  return (
    <div style={{
      display : 'flex', justifyContent:'center',alignItems:'center',width:'100%',height: '100vh'
    }}>
    <form style={{display:'flex', flexDirection:'column'}}
      onSubmit={onSubmitHandler}>
      <label>Email</label>
      <input type="email" value={Email} onChange={onEmailHandler}/>
      
      <label>Name</label>
      <input type="text" value={Name} onChange={onNameHandler}/>

      <label>Password</label>
      <input type="password" value={Password} onChange={onPasswordHandler}/>


      <label>Confirm Password</label>
      <input type="password" value={ConfirmPassword} onChange={onConfirmPasswordHandler}/>

      


      <br />
      <button>
        회원 가입
      </button>

    </form>
    </div>
  )
}


export default withRouter(RegisterPage)