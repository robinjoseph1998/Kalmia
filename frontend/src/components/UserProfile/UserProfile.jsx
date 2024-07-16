import React, { useContext, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import Cookies from 'js-cookie';
import { jwtDecode } from 'jwt-decode';
import { AnimatePresence, motion } from 'framer-motion';
import { Icon } from '@iconify/react';
import axios from 'axios';
import { AuthContext } from '../../context/AuthContext';
import instance from '../../api/AxiosInstance';
import { getTokenFromCookies } from '../../utils/CookiesManagement';
import { toastMessage } from '../../utils/Toast';

export default function UserProfile () {
  const { refresh, refreshData } = useContext(AuthContext);
  const [isEdit, setIsEdit] = useState(false);
  const navigate = useNavigate();
  const [userData, setUserData] = useState([]);

  const [profileImage, setProfileImage] = useState('/assets/noProfile.png');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');

  const token = getTokenFromCookies();

  useEffect(() => {
    const tokenData = JSON.parse(Cookies.get('accessToken'));
    const accessToken = jwtDecode(tokenData.token);
    const fetchData = async () => {
      try {
        const { data, status } = await instance.get('/auth/users');
        if (status === 200) {
          const filterUser = data.find(
            (obj) => obj.ID.toString() === accessToken.user_id
          );
          setUserData(filterUser);
          setUsername(filterUser.Username);
          setEmail(filterUser.Email);
          setProfileImage(filterUser.Photo || '/assets/noProfile.png');
        }
      } catch (err) {
        if (!err.response) {
          toastMessage(err?.message, 'error');
          navigate('/server-down');
        }
        toastMessage(err?.response?.data?.message, 'error');
      }
    };
    fetchData();
  }, [refresh, navigate]);

  const handleUpload = async (e) => {
    const file = e.target.files[0];
    console.log(file);
    if (file) {
      const formData = new FormData();
      formData.append('upload', file);

      try {
        const response = await axios.post(
          'http://[::1]:2727/auth/user/upload-photo',
          formData,
          {
            headers: {
              'Content-Type': 'multipart/form-data',
              Authorization: `Bearer ${token}`
            }
          }
        );
        if (response?.status === 200) {
          if (response?.data?.photo) {
            const image = response?.data?.photo;
            uploadImage(image);
          }
        }
      } catch (err) {
        if (!err.response) {
          toastMessage(err?.message, 'error');
          navigate('/server-down');
        }
        toastMessage(err?.response?.data?.message, 'error');
      }
    }
  };

  const uploadImage = async (image) => {
    try {
      const response = await instance.post('/auth/user/edit', {
        id: Number(userData.ID),
        photo: image
      });
      if (response?.status === 200) {
        toastMessage('user photo updated', 'success');
        refreshData();
      }
    } catch (err) {
      if (!err.response) {
        toastMessage(err?.message, 'error');
        navigate('/server-down');
      }
      toastMessage(err?.response?.data?.message, 'error');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      console.log(username);
      const response = await instance.post('/auth/user/edit', {
        id: Number(userData.ID),
        username,
        email
      });
      if (response?.status === 200) {
        toastMessage('user details updated', 'success');
        setIsEdit(false);
        refreshData();
      }
    } catch (err) {
      if (!err.response) {
        toastMessage(err?.message, 'error');
        navigate('/server-down');
      }
      toastMessage(err?.response?.data?.message, 'error');
    }
  };

  return (
    <>
      {isEdit && (
        <AnimatePresence
          id='defaultModal'
          tabindex='-1'
          aria-hidden='true'
          className=' flex  z-50 justify-center items-center w-full md:inset-0 h-modal md:h-full'
        >
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className='relative p-4 w-full max-w-2xl h-full md:h-auto'
          >
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className='relative p-4 bg-white rounded-lg shadow dark:bg-gray-800 sm:p-5'
            >
              <div className='flex justify-between items-center pb-4 mb-4 rounded-t border-b sm:mb-5 dark:border-gray-600'>
                <h3 className='text-lg font-semibold text-gray-900 dark:text-white'>
                  Edit User
                </h3>
                <button
                  onClick={() => setIsEdit(false)}
                  type='button'
                  className='text-gray-400 bg-transparent hover:bg-gray-200 hover:text-gray-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center dark:hover:bg-gray-600 dark:hover:text-white'
                  data-modal-toggle='defaultModal'
                >
                  <Icon icon='material-symbols:close' className='w-6 h-6' />

                  <span className='sr-only'>Close modal</span>
                </button>
              </div>

              <form action='#' onSubmit={handleSubmit}>
                <div className='grid gap-4 mb-4 '>
                  <div>
                    <label
                      htmlFor='username'
                      className='block mb-2 text-sm font-medium text-gray-900 dark:text-white'
                    >
                      Username
                    </label>
                    <input
                      type='text'
                      onChange={(e) => setUsername(e.target.value)}
                      value={username}
                      name='username'
                      id='username'
                      className='bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-primary-500 dark:focus:border-primary-500'
                      required=''
                    />
                  </div>
                  <div>
                    <label
                      htmlFor='email'
                      className='block mb-2 text-sm font-medium text-gray-900 dark:text-white'
                    >
                      Email
                    </label>
                    <input
                      onChange={(e) => setEmail(e.target.value)}
                      value={email}
                      type='email'
                      name='email'
                      id='email'
                      className='bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-primary-500 dark:focus:border-primary-500'
                      required=''
                    />
                  </div>
                </div>
                <div className='flex justify-center'>
                  <button
                    type='submit'
                    className=' text-white inline-flex items-center bg-primary-700 hover:bg-primary-800 focus:ring-4 focus:outline-none focus:ring-primary-300 font-medium rounded-lg text-sm px-5 py-2.5 text-center dark:bg-primary-600 dark:hover:bg-primary-700 dark:focus:ring-primary-800'
                  >
                    <Icon
                      icon='material-symbols:edit-outline'
                      className='w-6 h-6 text-yellow-500 dark:text-yellow-400'
                    />
                    Edit
                  </button>
                </div>
              </form>
            </motion.div>
          </motion.div>
        </AnimatePresence>
      )}

      {!isEdit && (
        <AnimatePresence className='container mx-auto p-4'>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className='max-w-lg mx-auto bg-white shadow-md rounded-lg p-6'
          >
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className='flex justify-between items-center mb-6'
            >
              <div className='relative'>
                <img
                  className='h-32 w-32 rounded-full border-4 border-white dark:border-gray-800'
                  src={profileImage}
                  alt='Profile'
                />
                <label
                  htmlFor='upload-button'
                  className='absolute bottom-0 right-0  text-blue-600 rounded-full p-2 hover:text-blue-500 cursor-pointer'
                >
                  <Icon icon='octicon:feed-plus-16' className='w-10 h-10' />
                  <input
                    id='upload-button'
                    type='file'
                    className='hidden'
                    onChange={handleUpload}
                  />
                </label>
              </div>

              <div className='flex flex-col gap-4'>
                <button
                  onClick={() => setIsEdit(true)}
                  className='bg-blue-500 px-5 rounded-lg text-white hover:bg-blue-700'
                >
                  Edit Profile
                </button>
                <Link
                  to={`/dashboard/user-changePassword?user_id=${userData.ID}`}
                >
                  <button className='bg-blue-500 px-5 rounded-lg text-white hover:bg-blue-700'>
                    Change Password
                  </button>
                </Link>
              </div>
            </motion.div>

            <div className='grid grid-cols-1 gap-4 sm:grid-cols-3'>
              <dt className='text-sm font-medium text-gray-500'>Username</dt>
              <dd className='mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2'>
                {userData.Username}
              </dd>
            </div>

            <div className='grid grid-cols-1 gap-4 sm:grid-cols-3 mt-4'>
              <dt className='text-sm font-medium text-gray-500'>
                Email Address
              </dt>
              <dd className='mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2'>
                {userData.Email}
              </dd>
            </div>
          </motion.div>
        </AnimatePresence>
      )}
    </>
  );
}
