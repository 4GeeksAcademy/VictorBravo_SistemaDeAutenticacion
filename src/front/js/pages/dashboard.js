import React, { useContext } from "react";
import { Context } from "../store/appContext";
import { Link } from "react-router-dom";
import "../../styles/dashboard.css";

export const Dashboard = ({ first_name }) => {
    const { store, actions } = useContext(Context);

    return (
        <div className="dashboard-container">
            <h1 className="dashboard-title">Bienvenido/a, {first_name}!</h1>
            <div className="row">
                <div className="col-md-6">
                    <div className="card mb-4 shadow-sm">
                        <div className="card-header">
                            <h5 className="card-title">Estadísticas de Uso</h5>
                        </div>
                        <div className="card-body">
                            <p>Accesos totales: <strong>{store.accessCount}</strong></p>
                            <p>Último acceso: <strong>{store.lastAccessDate}</strong></p>
                            <p>Sesiones activas: <strong>{store.activeSessions}</strong></p>
                        </div>
                    </div>
                </div>
                <div className="col-md-6">
                    <div className="card mb-4 shadow-sm">
                        <div className="card-header">
                            <h5 className="card-title">Acciones Recientes</h5>
                        </div>
                        <div className="card-body">
                            <ul className="list-group">
                                {store.actions.map((action, index) => (
                                    <li key={index} className="list-group-item d-flex justify-content-between">
                                        <span>{action.description}</span>
                                        <span className="text-muted">{action.date}</span>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
            <div className="row">
                <div className="col-md-12">
                    <div className="card shadow-sm">
                        <div className="card-header">
                            <h5 className="card-title">Información Detallada</h5>
                        </div>
                        <div className="card-body">
                            <h6 className="card-subtitle mb-2 text-muted">Demo Items</h6>
                            <ul className="list-group">
                                {store.demo.map((item, index) => {
                                    return (
                                        <li key={index} className="list-group-item d-flex justify-content-between" style={{ background: item.background }}>
                                            <Link to={"/single/" + index}>
                                                <span>Link to: {item.title}</span>
                                            </Link>
                                            {item.background === "orange" ? (
                                                <p style={{ color: item.initial }}>
                                                    Check store/flux.js scroll to the actions to see the code
                                                </p>
                                            ) : null}
                                            <button className="btn btn-success" onClick={() => actions.changeColor(index, "orange")}>
                                                Change Color
                                            </button>
                                        </li>
                                    );
                                })}
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};
