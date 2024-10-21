import React, { useContext, useEffect } from 'react';
import { Navigate } from 'react-router-dom';
import { Context } from '../store/appContext';

const ProtectedRoute = ({ children }) => {
    const { store } = useContext(Context);

    useEffect(() => {
        if (!store.isLogged) {
            alert("Esta ruta es solo para usuarios registrados. Por favor, inicia sesión.");
        }
    }, [store.isLogged]);

    // Si el usuario está logueado, muestra el componente hijo (Dashboard)
    if (store.isLogged) {
        return children;
    }

    // Si no está logueado, redirige a la página de inicio de sesión
    return <Navigate to="/" replace />;
};

export default ProtectedRoute;
