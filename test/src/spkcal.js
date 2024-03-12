import React from "react";
import ReactDOM from "react-dom";

export default
  class SPKCal extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      spk_latency: 0,
      prog_st: 0,
      reasonLatency: "",
      reasonAuto: "",
    };
  }

  spkcalLatencyClicked(ev) {
    console.log(ev);
    this.setState((state, props) => ({
      reasonLatency: ev.target.id
    }));
  }

  spkcalAutoClicked(ev) {
    console.log(ev);
    this.setState((state, props) => ({
      reasonAuto: ev.target.id
    }));
  }

  render() {
    return (<div>
      <h2>Speaker Latency</h2>
      <p>
        This section setup the latency between audio signal output from hardware terminal and audable from speaker<br />
      </p>
      <p>
        <label>Set latency in milliseconds:<br />
          <input type="number" name="spkcal_latency_text" id="spkcal_latency_text" value={this.state.spk_latency} />
        </label>
        <button type="button" id="set" onClick={this.spkcalLatencyClicked.bind(this)}>Set</button>
        <button type="button" id="get" onClick={this.spkcalLatencyClicked.bind(this)}>Get</button>
        <em>{this.state.reasonLatency}</em>
        <br />
      </p>
      <p>
        The auto calibration process will take about 30 seconds, take device closer to speaker before start.<br />
        <button type="button" id="auto" onClick={this.spkcalAutoClicked.bind(this)}>Start Auto Calibration</button>
        <em>{this.state.reasonAuto}</em>
      </p>
    </div>);
  }
};

// ReactDOM.render(
//   <SPKCal />,
//   document.getElementById("root")
// );
